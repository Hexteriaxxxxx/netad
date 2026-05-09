# main.py — NETAD Security System

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, Response
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix
from consensus import get_consensus, check_heartbeat
from block import Block
from database import (
    add_log, get_logs, get_sessions, delete_session,
    get_blacklist, add_to_blacklist, forgive_ip,
    get_whitelist, add_to_whitelist, remove_from_whitelist,
    get_ai_logs, create_session, update_session_heartbeat,
    add_ai_log, get_user, cleanup_used_tokens,
    add_chat_log, get_chat_logs
)
from dotenv import load_dotenv
import os
import subprocess
import sys
import threading
import time
import secrets
import cv2

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is not set in .env — refusing to start.")

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', 'http://localhost:5000')
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGIN)

# ── CAMERA CONFIG ──
CAMERA_URLS = {
    1: os.environ.get('CAMERA_1_URL', ''),
    2: os.environ.get('CAMERA_2_URL', ''),
}

# Track consensus state globally so camera routes can check it
_consensus_granted = False
_consensus_lock = threading.Lock()

def set_consensus_state(granted: bool):
    global _consensus_granted
    with _consensus_lock:
        _consensus_granted = granted

def is_consensus_granted() -> bool:
    with _consensus_lock:
        return _consensus_granted

# ── CAMERA STREAM GENERATOR ──
def generate_camera_stream(cam_id: int):
    """
    Pulls frames from the IP camera via OpenCV and yields MJPEG frames.
    Only streams if consensus is granted.
    """
    url = CAMERA_URLS.get(cam_id, '')
    if not url:
        yield b''
        return

    cap = None
    try:
        cap = cv2.VideoCapture(url)
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

        while True:
            if not is_consensus_granted():
                # Consensus lost — stop streaming
                break

            ret, frame = cap.read()
            if not ret:
                # Camera disconnected — try to reconnect
                cap.release()
                time.sleep(2)
                cap = cv2.VideoCapture(url)
                continue

            # Encode frame as JPEG
            ret, buffer = cv2.imencode(
                '.jpg', frame,
                [cv2.IMWRITE_JPEG_QUALITY, 75]
            )
            if not ret:
                continue

            yield (
                b'--frame\r\n'
                b'Content-Type: image/jpeg\r\n\r\n'
                + buffer.tobytes()
                + b'\r\n'
            )

            time.sleep(0.033)  # ~30fps cap

    except Exception as e:
        print(f"Camera {cam_id} stream error: {e}")
    finally:
        if cap:
            cap.release()

# ── CAMERA ROUTES ──
@app.route('/api/camera/<int:cam_id>/stream')
def camera_stream(cam_id: int):
    """
    MJPEG stream endpoint. Only accessible when:
    1. User has an active session
    2. 6/6 consensus is currently granted
    """
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    if cam_id not in CAMERA_URLS:
        return jsonify({'error': 'invalid camera id'}), 404

    if not CAMERA_URLS.get(cam_id):
        return jsonify({'error': f'CAMERA_{cam_id}_URL not configured in .env'}), 503

    if not is_consensus_granted():
        return jsonify({'error': 'access denied — consensus not met'}), 403

    return Response(
        generate_camera_stream(cam_id),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

@app.route('/api/camera/status')
def camera_status():
    """Returns whether cameras are accessible right now."""
    granted = is_consensus_granted()
    return jsonify({
        'accessible': granted,
        'cameras': {
            str(cam_id): {
                'configured': bool(url),
                'accessible': granted and bool(url)
            }
            for cam_id, url in CAMERA_URLS.items()
        }
    })

# ── CSRF TOKEN STORE ──
_csrf_tokens: dict = {}
_csrf_lock = threading.Lock()

def generate_csrf() -> str:
    token = secrets.token_hex(32)
    with _csrf_lock:
        _csrf_tokens[token] = time.time() + 300
        expired = [t for t, exp in _csrf_tokens.items() if exp < time.time()]
        for t in expired:
            del _csrf_tokens[t]
    return token

def validate_csrf(token: str) -> bool:
    with _csrf_lock:
        if token not in _csrf_tokens:
            return False
        if _csrf_tokens[token] < time.time():
            del _csrf_tokens[token]
            return False
        del _csrf_tokens[token]
        return True

# ── START ALL NODES ──
def start_nodes():
    base = os.path.dirname(os.path.abspath(__file__))
    node_files = [os.path.join(base, 'nodes', f'node{i}.py') for i in range(1, 7)]
    for f in node_files:
        if os.path.exists(f):
            subprocess.Popen([sys.executable, f], cwd=base)
            print(f"Started {f}")
    time.sleep(2)

# ── HEARTBEAT MONITOR ──
def heartbeat_monitor():
    node_names = ['password', 'timestamp', 'ip_whitelist', 'digital_sig', 'session_token', 'rate_limit']
    while True:
        try:
            alive = check_heartbeat()
            all_alive = all(alive)
            # Update global consensus camera gate
            # Cameras stay open as long as at least one active session exists
            # and all nodes are alive
            if not all_alive:
                set_consensus_state(False)
                socketio.emit('camera_access', {'accessible': False, 'reason': 'node offline'})
            socketio.emit('node_status', {
                'nodes': [{'id': i+1, 'name': node_names[i], 'alive': alive[i]} for i in range(len(alive))]
            })
        except Exception as e:
            print(f"Heartbeat monitor error: {e}")
        time.sleep(10)

# ── TOKEN CLEANUP ──
def token_cleanup_worker():
    while True:
        try:
            cleanup_used_tokens()
        except Exception as e:
            print(f"Token cleanup error: {e}")
        time.sleep(600)

# ── ROUTES ──

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('index'))
    user = session.get('user', 'admin')
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    user = session.get('user')
    if user:
        delete_session(user)
    session.clear()
    set_consensus_state(False)
    return redirect(url_for('index'))

@app.route('/api/csrf', methods=['GET'])
def get_csrf():
    return jsonify({'csrf_token': generate_csrf()})

@app.route('/api/token', methods=['GET'])
def get_token():
    return jsonify({'token': secrets.token_hex(32)})

# ── LOGIN ──
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'granted': False, 'error': 'invalid request'})

    username      = data.get('username', '').strip()
    password      = data.get('password', '')
    csrf_token    = data.get('csrf_token', '')
    session_token = data.get('session_token', '')
    client_ip     = request.remote_addr

    # Layer: CSRF
    if not validate_csrf(csrf_token):
        add_log(username, client_ip, 'DENIED', 'Invalid CSRF token')
        return jsonify({'granted': False, 'error': 'invalid csrf token'})

    # Layer: AI anomaly
    try:
        from ai.anomaly import is_suspicious
        suspicious, score = is_suspicious(client_ip, username)
        if suspicious:
            add_log(username, client_ip, 'SUSPICIOUS', f'AI flagged (score={score:.3f})')
            add_ai_log(client_ip, username, 'Suspicious login pattern detected', score, True)
            socketio.emit('ai_alert', {
                'ip': client_ip, 'username': username,
                'score': float(score),
                'message': f'Anomalous login behavior detected from {client_ip}'
            })
            _notify_guard(f"🚨 AI flagged suspicious login attempt from {client_ip} (user: '{username}', score: {score:.3f})")
            return jsonify({'granted': False, 'error': 'suspicious behavior detected',
                            'steps': [{'layer': 'AI Anomaly Detection', 'result': 'FAIL'}]})
    except Exception as e:
        print(f"AI check error: {e}")

    # Layer: Block hash
    block = Block({'username': username, 'password': password, 'ip': client_ip})

    # Layer: Heartbeat
    alive = check_heartbeat()
    if not all(alive):
        dead = [i + 1 for i, a in enumerate(alive) if not a]
        add_log(username, client_ip, 'DENIED', f'Nodes {dead} offline')
        return jsonify({'granted': False, 'error': f'nodes {dead} are offline'})

    # Layer: Sign block
    try:
        from security.signer import sign_request
        signature = sign_request(block.hash)
    except Exception as e:
        print(f"Signing error: {e}")
        signature = ''

    if not session_token:
        session_token = secrets.token_hex(32)

    payload = {
        'type': 'validate',
        'username': username,
        'password': password,
        'ip': client_ip,
        'timestamp': block.timestamp,
        'hash': block.hash,
        'signature': signature,
        'session_token': session_token,
    }

    # Layer: 6/6 Consensus
    result, votes = get_consensus(payload)
    granted = result == 'GRANTED'

    add_log(username, client_ip, result)

    if granted:
        user_data = get_user(username)
        role = user_data['role'] if user_data else 'Member'
        sess_token = secrets.token_hex(32)
        create_session(username, client_ip, role, sess_token)
        session['user'] = username
        session['token'] = sess_token
        # ── Open camera access on successful 6/6 consensus ──
        set_consensus_state(True)
        socketio.emit('camera_access', {'accessible': True, 'reason': '6/6 consensus granted'})

    socketio.emit('login_attempt', {
        'username': username, 'ip': client_ip,
        'result': result, 'votes': votes
    })

    layer_names = [
        'Rate Limiting', 'Password Verification', 'Request Timestamp',
        'IP Access Control', 'Digital Signature', 'Session Management'
    ]
    steps = [
        {'layer': layer_names[i], 'result': votes[i] if i < len(votes) else 'SKIP'}
        for i in range(6)
    ]

    return jsonify({
        'granted': granted, 'user': username,
        'error': '' if granted else 'authentication failed',
        'steps': steps, 'votes': votes
    })

# ── NODE STATUS ──
@app.route('/api/node-status')
def node_status():
    alive = check_heartbeat()
    node_names = ['password', 'timestamp', 'ip_whitelist', 'digital_sig', 'session_token', 'rate_limit']
    return jsonify({name: alive[i] for i, name in enumerate(node_names)})

# ── LOGS ──
@app.route('/api/logs')
def api_logs():
    logs = get_logs(50)
    result = []
    for l in logs:
        row = dict(l)
        if row.get('timestamp'):
            row['timestamp'] = str(row['timestamp'])
        result.append(row)
    return jsonify(result)

# ── BLACKLIST ──
@app.route('/api/blacklist')
def api_blacklist():
    bl = get_blacklist()
    result = []
    for b in bl:
        row = dict(b)
        if row.get('blocked_until'):
            row['blocked_until'] = str(row['blocked_until'])
        result.append(row)
    return jsonify(result)

@app.route('/api/blacklist/add', methods=['POST'])
def api_blacklist_add():
    data = request.get_json()
    add_to_blacklist(data['ip'], data.get('type', 'temporary'))
    return jsonify({'success': True})

@app.route('/api/blacklist/forgive', methods=['POST'])
def api_blacklist_forgive():
    data = request.get_json()
    forgive_ip(data['ip'])
    return jsonify({'success': True})

# ── WHITELIST ──
@app.route('/api/whitelist')
def api_whitelist():
    wl = get_whitelist()
    return jsonify([dict(w) for w in wl])

@app.route('/api/whitelist/add', methods=['POST'])
def api_whitelist_add():
    data = request.get_json()
    add_to_whitelist(data['ip'], data.get('label', 'New device'))
    return jsonify({'success': True})

@app.route('/api/whitelist/remove', methods=['POST'])
def api_whitelist_remove():
    data = request.get_json()
    remove_from_whitelist(data['ip'])
    return jsonify({'success': True})

# ── SESSIONS ──
@app.route('/api/sessions')
def api_sessions():
    sess = get_sessions()
    result = []
    for s in sess:
        row = dict(s)
        if row.get('last_seen'):
            row['last_seen'] = str(row['last_seen'])
        if row.get('created_at'):
            row['created_at'] = str(row['created_at'])
        result.append(row)
    return jsonify(result)

@app.route('/api/sessions/kick', methods=['POST'])
def api_sessions_kick():
    data = request.get_json()
    delete_session(data['username'])
    socketio.emit('session_kicked', {'username': data['username']})
    return jsonify({'success': True})

@app.route('/api/session/heartbeat', methods=['POST'])
def api_session_heartbeat():
    data = request.get_json()
    update_session_heartbeat(data.get('username', ''))
    return jsonify({'ok': True})

# ── AI LOGS ──
@app.route('/api/ai-logs')
def api_ai_logs():
    logs = get_ai_logs(20)
    result = []
    for l in logs:
        row = dict(l)
        if row.get('timestamp'):
            row['timestamp'] = str(row['timestamp'])
        result.append(row)
    return jsonify(result)

# ── GUARD CHAT ──
def _get_system_context() -> str:
    try:
        logs     = get_logs(10)
        ai_logs  = get_ai_logs(5)
        sessions = get_sessions()
        bl       = get_blacklist()
        wl       = get_whitelist()
        alive    = check_heartbeat()
        node_names = ['password', 'timestamp', 'ip_whitelist', 'digital_sig', 'session_token', 'rate_limit']
        node_status = {node_names[i]: alive[i] for i in range(6)}
        ctx  = "=== LIVE NETAD SYSTEM STATE ===\n"
        ctx += f"Node status: {node_status}\n"
        ctx += f"Camera access: {'OPEN' if is_consensus_granted() else 'LOCKED'}\n\n"
        ctx += "Recent access logs (last 10):\n"
        for l in logs:
            ctx += f"  [{l.get('timestamp','')}] {l.get('result','')} — user={l.get('username','')} ip={l.get('ip','')} reason={l.get('reason','')}\n"
        ctx += "\nAI anomaly flags (last 5):\n"
        for a in ai_logs:
            ctx += f"  [{a.get('timestamp','')}] ip={a.get('ip','')} user={a.get('username','')} score={a.get('score','')} flagged={a.get('flagged','')}\n"
        ctx += f"\nActive sessions: {len([s for s in sessions if s.get('online')])}\n"
        ctx += f"Blacklisted IPs: {len(bl)}\n"
        ctx += f"Whitelisted IPs: {len(wl)}\n"
        return ctx
    except Exception as e:
        return f"(Could not fetch live context: {e})"

def _notify_guard(message: str):
    try:
        add_chat_log('system', message)
        socketio.emit('chat_message', {'role': 'system', 'message': message})
    except Exception:
        pass

@app.route('/api/chat', methods=['POST'])
def api_chat():
    data = request.get_json()
    user_message = data.get('message', '').strip()
    if not user_message:
        return jsonify({'error': 'empty message'})
    groq_api_key = os.environ.get('GROQ_API_KEY')
    if not groq_api_key:
        return jsonify({'reply': 'Groq API key not configured.'})
    add_chat_log('user', user_message)
    system_context = _get_system_context()
    chat_history   = get_chat_logs(20)
    messages = [{
        'role': 'system',
        'content': (
            "You are NETAD Guard, an AI security officer for the NETAD multi-layer camera security system. "
            "You have real-time access to login logs, AI anomaly alerts, node status, blacklist, whitelist, active sessions, and camera access state. "
            "You speak in a professional but concise tone. "
            "When the user asks you to perform an action (block IP, forgive IP, kick session, add to whitelist), "
            "respond with a JSON action block in your reply like this:\n"
            "ACTION:{\"action\": \"block_ip\", \"ip\": \"192.168.1.9\"}\n"
            "Available actions: block_ip, forgive_ip, kick_session, add_whitelist, remove_whitelist.\n"
            "Always explain what you are doing and why.\n\n"
            + system_context
        )
    }]
    for msg in chat_history[-16:]:
        role = msg.get('role', 'user')
        if role == 'system':
            continue
        messages.append({'role': role, 'content': msg.get('message', '')})
    messages.append({'role': 'user', 'content': user_message})
    try:
        from groq import Groq
        client = Groq(api_key=groq_api_key)
        response = client.chat.completions.create(
            model='llama3-70b-8192', messages=messages,
            max_tokens=512, temperature=0.4,
        )
        reply = response.choices[0].message.content.strip()
        action_result = _execute_action(reply)
        add_chat_log('assistant', reply)
        socketio.emit('chat_message', {'role': 'assistant', 'message': reply})
        return jsonify({'reply': reply, 'action_result': action_result})
    except Exception as e:
        return jsonify({'reply': f'Guard unavailable: {e}'})

def _execute_action(reply: str) -> dict:
    import json as _json, re
    match = re.search(r'ACTION:(\{.*?\})', reply, re.DOTALL)
    if not match:
        return {}
    try:
        action = _json.loads(match.group(1))
        act = action.get('action', '')
        ip  = action.get('ip', '')
        username = action.get('username', '')
        if act == 'block_ip' and ip:
            add_to_blacklist(ip, 'temporary', 1800)
            socketio.emit('guard_action', {'action': 'block_ip', 'ip': ip})
            return {'executed': 'block_ip', 'ip': ip}
        elif act == 'forgive_ip' and ip:
            forgive_ip(ip)
            socketio.emit('guard_action', {'action': 'forgive_ip', 'ip': ip})
            return {'executed': 'forgive_ip', 'ip': ip}
        elif act == 'kick_session' and username:
            delete_session(username)
            socketio.emit('session_kicked', {'username': username})
            return {'executed': 'kick_session', 'username': username}
        elif act == 'add_whitelist' and ip:
            add_to_whitelist(ip, action.get('label', 'Guard approved'))
            return {'executed': 'add_whitelist', 'ip': ip}
        elif act == 'remove_whitelist' and ip:
            remove_from_whitelist(ip)
            return {'executed': 'remove_whitelist', 'ip': ip}
    except Exception as e:
        print(f"Action parse error: {e}")
    return {}

@app.route('/api/chat/history', methods=['GET'])
def api_chat_history():
    logs = get_chat_logs(50)
    result = []
    for l in logs:
        row = dict(l)
        if row.get('timestamp'):
            row['timestamp'] = str(row['timestamp'])
        result.append(row)
    return jsonify(result)

# ── MAIN ──
if __name__ == '__main__':
    print("Starting NETAD Security System...")
    start_nodes()
    threading.Thread(target=heartbeat_monitor, daemon=True).start()
    threading.Thread(target=token_cleanup_worker, daemon=True).start()
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    socketio.run(app, host=host, port=port, debug=False)
