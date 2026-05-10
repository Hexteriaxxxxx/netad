# main.py — NETAD Security System (Railway-compatible, single-process nodes)

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, Response
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix
from block import Block
from database import (
    add_log, get_logs, get_sessions, delete_session,
    get_blacklist, add_to_blacklist, forgive_ip,
    get_whitelist, add_to_whitelist, remove_from_whitelist,
    get_ai_logs, create_session, update_session_heartbeat,
    add_ai_log, get_user, cleanup_used_tokens,
    add_chat_log, get_chat_logs,
    register_device, get_device, get_all_devices,
    approve_device, reject_device, delete_device, get_pending_devices,
    is_whitelisted, is_blacklisted, get_all_failed_count,
    claim_token, get_device_public_key, clear_rate_limit
)
from dotenv import load_dotenv
import os
import threading
import time
import secrets
import json
import base64

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is not set in .env — refusing to start.")

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', '*')
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGIN)

# ── CAMERA CONFIG ──
CAMERA_URLS = {
    1: os.environ.get('CAMERA_1_URL', ''),
    2: os.environ.get('CAMERA_2_URL', ''),
}

_consensus_granted = False
_consensus_lock = threading.Lock()

def set_consensus_state(granted: bool):
    global _consensus_granted
    with _consensus_lock:
        _consensus_granted = granted

def is_consensus_granted() -> bool:
    with _consensus_lock:
        return _consensus_granted

# ── CAMERA STREAM ──
def generate_camera_stream(cam_id: int):
    url = CAMERA_URLS.get(cam_id, '')
    if not url:
        yield b''
        return
    try:
        import cv2
        cap = cv2.VideoCapture(url)
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        while True:
            if not is_consensus_granted():
                break
            ret, frame = cap.read()
            if not ret:
                cap.release()
                time.sleep(2)
                cap = cv2.VideoCapture(url)
                continue
            ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 75])
            if not ret:
                continue
            yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            time.sleep(0.033)
    except Exception as e:
        print(f"Camera {cam_id} error: {e}")

@app.route('/api/camera/<int:cam_id>/stream')
def camera_stream(cam_id: int):
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    if not CAMERA_URLS.get(cam_id):
        return jsonify({'error': f'CAMERA_{cam_id}_URL not configured'}), 503
    if not is_consensus_granted():
        return jsonify({'error': 'consensus not met'}), 403
    return Response(generate_camera_stream(cam_id), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/api/camera/status')
def camera_status():
    granted = is_consensus_granted()
    return jsonify({'accessible': granted, 'cameras': {str(i): {'configured': bool(u), 'accessible': granted and bool(u)} for i, u in CAMERA_URLS.items()}})

# ══════════════════════════════════════════════════
# INLINE NODES
# ══════════════════════════════════════════════════

def node1_password(payload):
    import bcrypt, hashlib
    username = payload.get('username', '')
    password = payload.get('password', '')
    if not username or not password:
        return 'FAIL'
    try:
        user = get_user(username)
        if not user:
            return 'FAIL'
        stored = user['password_hash']
        if stored.startswith('$2b$') or stored.startswith('$2a$'):
            result = bcrypt.checkpw(password.encode(), stored.encode())
        else:
            result = stored == hashlib.sha256(password.encode()).hexdigest()
        print(f"Node 1 {'PASS' if result else 'FAIL'}: {username}")
        return 'PASS' if result else 'FAIL'
    except Exception as e:
        print(f"Node 1 error: {e}")
        return 'FAIL'

def node2_timestamp(payload):
    import time as t
    ts = payload.get('timestamp', 0)
    age = t.time() - ts
    if age > 30 or age < 0:
        print(f"Node 2 FAIL: age={age:.1f}s")
        return 'FAIL'
    print(f"Node 2 PASS: {age:.1f}s old")
    return 'PASS'

def node3_ip_whitelist(payload):
    ip = payload.get('ip', '')
    if is_whitelisted(ip):
        print(f"Node 3 PASS: {ip} whitelisted")
        return 'PASS'
    print(f"Node 3 FAIL: {ip} not whitelisted")
    return 'FAIL'

def node4_device_signature(payload):
    username  = payload.get('username', '')
    device_id = payload.get('device_id', '')
    sig_b64   = payload.get('device_signature', '')
    message   = payload.get('device_message', '')
    if not all([username, device_id, sig_b64, message]):
        print("Node 4 FAIL: missing device auth fields")
        return 'FAIL'
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicNumbers, SECP256R1
        from cryptography.hazmat.primitives import hashes
        pub_jwk_str = get_device_public_key(username, device_id)
        if not pub_jwk_str:
            print(f"Node 4 FAIL: device not approved for '{username}'")
            return 'FAIL'
        jwk = json.loads(pub_jwk_str)
        def b64u(s):
            pad = 4 - len(s) % 4
            if pad != 4: s += '=' * pad
            return int.from_bytes(base64.urlsafe_b64decode(s), 'big')
        pub_key = EllipticCurvePublicNumbers(x=b64u(jwk['x']), y=b64u(jwk['y']), curve=SECP256R1()).public_key()
        sig_bytes = base64.b64decode(sig_b64)
        r, s = sig_bytes[:32], sig_bytes[32:]
        def enc(n):
            n = n.lstrip(b'\x00') or b'\x00'
            if n[0] & 0x80: n = b'\x00' + n
            return bytes([0x02, len(n)]) + n
        body = enc(r) + enc(s)
        sig_der = bytes([0x30, len(body)]) + body
        pub_key.verify(sig_der, message.encode(), ECDSA(hashes.SHA256()))
        print(f"Node 4 PASS: ECDSA valid for '{username}'")
        return 'PASS'
    except Exception as e:
        print(f"Node 4 FAIL: {e}")
        return 'FAIL'

def node5_session_token(payload):
    token = payload.get('session_token', '')
    if not token:
        return 'FAIL'
    if claim_token(token):
        print("Node 5 PASS: token claimed")
        return 'PASS'
    print("Node 5 FAIL: token already used")
    return 'FAIL'

def node6_rate_limit(payload):
    ip = payload.get('ip', 'unknown')
    MAX = 5
    if is_blacklisted(ip):
        print(f"Node 6 FAIL: {ip} blacklisted")
        return 'FAIL'
    # Whitelisted IPs bypass rate limiting — already trusted via Node 3 + Node 4
    if is_whitelisted(ip):
        count = get_all_failed_count(ip)
        print(f"Node 6 PASS: {ip} whitelisted — rate limit skipped ({count} prev failures)")
        return 'PASS'
    count = get_all_failed_count(ip)
    if count >= MAX:
        add_to_blacklist(ip, 'temporary', 1800)
        print(f"Node 6 FAIL: {ip} rate limited ({count} attempts)")
        return 'FAIL'
    print(f"Node 6 PASS: {ip} — {count}/{MAX}")
    return 'PASS'

INLINE_NODES = [
    ('Rate Limiting',         node6_rate_limit),
    ('Password Verification', node1_password),
    ('Request Timestamp',     node2_timestamp),
    ('IP Access Control',     node3_ip_whitelist),
    ('Device Signature',      node4_device_signature),
    ('Session Management',    node5_session_token),
]

def run_consensus(payload):
    votes = [None] * len(INLINE_NODES)
    def run_node(i, name, fn):
        try:
            votes[i] = fn(payload)
        except Exception as e:
            print(f"Node {i+1} ({name}) exception: {e}")
            votes[i] = 'FAIL'
    threads = [threading.Thread(target=run_node, args=(i, name, fn)) for i, (name, fn) in enumerate(INLINE_NODES)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=6)
    votes = [v if v else 'FAIL' for v in votes]
    steps = [{'layer': INLINE_NODES[i][0], 'result': votes[i]} for i in range(len(INLINE_NODES))]
    granted = all(v == 'PASS' for v in votes)
    print(f"Consensus: {votes} → {'GRANTED' if granted else 'DENIED'}")
    return ('GRANTED' if granted else 'DENIED'), votes, steps

# ── CSRF ──
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

def token_cleanup_worker():
    while True:
        try:
            cleanup_used_tokens()
        except Exception as e:
            print(f"Token cleanup error: {e}")
        time.sleep(600)

def _notify_guard(message: str):
    try:
        add_chat_log('system', message)
        socketio.emit('chat_message', {'role': 'system', 'message': message})
    except Exception:
        pass

# ══════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html', user=session.get('user', 'admin'))

@app.route('/logout')
def logout():
    user = session.get('user')
    if user:
        delete_session(user)
    session.clear()
    set_consensus_state(False)
    return redirect(url_for('index'))

@app.route('/api/csrf')
def get_csrf():
    return jsonify({'csrf_token': generate_csrf()})

@app.route('/api/token')
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
    session_token = data.get('session_token', '') or secrets.token_hex(32)
    client_ip     = request.remote_addr

    if not validate_csrf(csrf_token):
        add_log(username, client_ip, 'DENIED', 'Invalid CSRF token')
        return jsonify({'granted': False, 'error': 'invalid csrf token'})

    try:
        from ai.anomaly import is_suspicious
        suspicious, score = is_suspicious(client_ip, username)
        if suspicious:
            add_log(username, client_ip, 'SUSPICIOUS', f'AI flagged (score={score:.3f})')
            add_ai_log(client_ip, username, 'Suspicious login pattern detected', score, True)
            socketio.emit('ai_alert', {'ip': client_ip, 'username': username, 'score': float(score), 'message': f'Anomalous login from {client_ip}'})
            _notify_guard(f"🚨 AI flagged suspicious login from {client_ip} (user: '{username}', score: {score:.3f})")
            return jsonify({'granted': False, 'error': 'suspicious behavior detected', 'steps': [{'layer': 'AI Anomaly', 'result': 'FAIL'}]})
    except Exception as e:
        print(f"AI check error: {e}")

    block = Block({'username': username, 'password': password, 'ip': client_ip})

    try:
        from security.signer import sign_request
        signature = sign_request(block.hash)
    except Exception as e:
        print(f"Signing error (non-fatal): {e}")
        signature = ''

    payload = {
        'username':         username,
        'password':         password,
        'ip':               client_ip,
        'timestamp':        block.timestamp,
        'hash':             block.hash,
        'signature':        signature,
        'session_token':    session_token,
        'device_id':        data.get('device_id', ''),
        'device_signature': data.get('device_signature', ''),
        'device_message':   data.get('device_message', ''),
    }

    result, votes, steps = run_consensus(payload)
    granted = result == 'GRANTED'
    add_log(username, client_ip, result)

    if granted:
        user_data = get_user(username)
        role = user_data['role'] if user_data else 'Member'
        sess_token = secrets.token_hex(32)
        create_session(username, client_ip, role, sess_token)
        session['user'] = username
        session['token'] = sess_token
        set_consensus_state(True)
        socketio.emit('camera_access', {'accessible': True, 'reason': '6/6 consensus granted'})

    socketio.emit('login_attempt', {'username': username, 'ip': client_ip, 'result': result, 'votes': votes})
    return jsonify({'granted': granted, 'user': username, 'error': '' if granted else 'authentication failed', 'steps': steps, 'votes': votes})

@app.route('/api/node-status')
def node_status():
    return jsonify({'password': True, 'timestamp': True, 'ip_whitelist': True, 'digital_sig': True, 'session_token': True, 'rate_limit': True})

@app.route('/api/logs')
def api_logs():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    return jsonify([{**dict(l), 'timestamp': str(l['timestamp'])} for l in get_logs(50)])

@app.route('/api/blacklist')
def api_blacklist():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    result = []
    for b in get_blacklist():
        row = dict(b)
        if row.get('blocked_until'): row['blocked_until'] = str(row['blocked_until'])
        result.append(row)
    return jsonify(result)

@app.route('/api/blacklist/add', methods=['POST'])
def api_blacklist_add():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    add_to_blacklist(data['ip'], data.get('type', 'temporary'))
    return jsonify({'success': True})

@app.route('/api/clear-rate-limit', methods=['POST'])
def api_clear_rate_limit():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    ip = request.get_json().get('ip', '')
    if not ip: return jsonify({'error': 'missing ip'}), 400
    clear_rate_limit(ip)
    socketio.emit('guard_action', {'action': 'clear_rate_limit', 'ip': ip})
    return jsonify({'success': True})

@app.route('/api/blacklist/forgive', methods=['POST'])
def api_blacklist_forgive():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    ip = request.get_json()['ip']
    forgive_ip(ip)
    clear_rate_limit(ip)  # also wipe failed attempt logs so they can retry
    return jsonify({'success': True})

@app.route('/api/whitelist')
def api_whitelist():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    return jsonify([dict(w) for w in get_whitelist()])

@app.route('/api/whitelist/add', methods=['POST'])
def api_whitelist_add():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    add_to_whitelist(data['ip'], data.get('label', 'New device'))
    return jsonify({'success': True})

@app.route('/api/whitelist/remove', methods=['POST'])
def api_whitelist_remove():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    remove_from_whitelist(request.get_json()['ip'])
    return jsonify({'success': True})

@app.route('/api/sessions')
def api_sessions():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    result = []
    for s in get_sessions():
        row = dict(s)
        if row.get('last_seen'): row['last_seen'] = str(row['last_seen'])
        if row.get('created_at'): row['created_at'] = str(row['created_at'])
        result.append(row)
    return jsonify(result)

@app.route('/api/sessions/kick', methods=['POST'])
def api_sessions_kick():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    delete_session(data['username'])
    socketio.emit('session_kicked', {'username': data['username']})
    return jsonify({'success': True})

@app.route('/api/session/heartbeat', methods=['POST'])
def api_session_heartbeat():
    update_session_heartbeat(request.get_json().get('username', ''))
    return jsonify({'ok': True})

@app.route('/api/ai-logs')
def api_ai_logs():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    return jsonify([{**dict(l), 'timestamp': str(l['timestamp'])} for l in get_ai_logs(20)])

# ── GUARD CHAT ──
def _get_system_context() -> str:
    try:
        logs     = get_logs(10)
        ai_logs  = get_ai_logs(5)
        sessions = get_sessions()
        bl       = get_blacklist()
        wl       = get_whitelist()
        pending  = get_pending_devices()
        ctx  = "=== LIVE NETAD SYSTEM STATE ===\n"
        ctx += f"Camera access: {'OPEN' if is_consensus_granted() else 'LOCKED'}\n"
        ctx += f"All 6 nodes: INLINE (always active)\n"
        ctx += f"Pending device approvals: {len(pending)}\n\n"
        ctx += "Recent logs:\n"
        for l in logs:
            ctx += f"  [{l.get('timestamp','')}] {l.get('result','')} — user={l.get('username','')} ip={l.get('ip','')} reason={l.get('reason','')}\n"
        ctx += "\nAI flags:\n"
        for a in ai_logs:
            ctx += f"  ip={a.get('ip','')} user={a.get('username','')} score={a.get('score','')} flagged={a.get('flagged','')}\n"
        ctx += f"\nActive sessions: {len([s for s in sessions if s.get('online')])}\n"
        ctx += f"Blacklisted: {len(bl)} IPs\nWhitelisted: {len(wl)} IPs\n"
        return ctx
    except Exception as e:
        return f"(context error: {e})"

@app.route('/api/chat', methods=['POST'])
def api_chat():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    user_message = data.get('message', '').strip()
    if not user_message: return jsonify({'error': 'empty'})
    groq_api_key = os.environ.get('GROQ_API_KEY')
    if not groq_api_key: return jsonify({'reply': 'Groq API key not configured.'})
    add_chat_log('user', user_message)
    chat_history = get_chat_logs(20)
    messages = [{'role': 'system', 'content': (
        "You are NETAD Guard, an AI security officer for the NETAD multi-layer camera security system. "
        "You have real-time access to login logs, AI anomaly alerts, node status, device approvals, blacklist, whitelist, and active sessions. "
        "You speak professionally and concisely. "
        "When asked to perform an action, you MUST include this JSON block in your reply — do not just describe it, actually include it:\n"
        "ACTION:{\"action\": \"block_ip\", \"ip\": \"x.x.x.x\"}\n"
        "Available actions and when to use them:\n"
        "  block_ip — block an IP address (requires: ip)\n"
        "  forgive_ip — remove IP from blacklist (requires: ip)\n"
        "  clear_rate_limit — clear failed login count for an IP so they can try again (requires: ip)\n"
        "  kick_session — force logout a user (requires: username)\n"
        "  add_whitelist — add IP to whitelist (requires: ip, label)\n"
        "  remove_whitelist — remove IP from whitelist (requires: ip)\n"
        "When a user says 'let X in' or 'clear rate limit for X', use clear_rate_limit with their IP from the logs.\n\n"
        + _get_system_context()
    )}]
    for msg in chat_history[-16:]:
        if msg.get('role') == 'system': continue
        messages.append({'role': msg.get('role', 'user'), 'content': msg.get('message', '')})
    messages.append({'role': 'user', 'content': user_message})
    try:
        from groq import Groq
        client = Groq(api_key=groq_api_key)
        response = client.chat.completions.create(model='llama-3.3-70b-versatile', messages=messages, max_tokens=1024, temperature=0.4)
        reply = response.choices[0].message.content.strip()
        action_result = _execute_action(reply)
        add_chat_log('assistant', reply)
        socketio.emit('chat_message', {'role': 'assistant', 'message': reply})
        return jsonify({'reply': reply, 'action_result': action_result})
    except Exception as e:
        return jsonify({'reply': f'Guard unavailable: {e}'})

def _execute_action(reply: str) -> dict:
    import re
    match = re.search(r'ACTION:(\{.*?\})', reply, re.DOTALL)
    if not match: return {}
    try:
        import json as _j
        action = _j.loads(match.group(1))
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
        elif act == 'clear_rate_limit' and ip:
            clear_rate_limit(ip)
            socketio.emit('guard_action', {'action': 'clear_rate_limit', 'ip': ip})
            return {'executed': 'clear_rate_limit', 'ip': ip}
        elif act == 'remove_whitelist' and ip:
            remove_from_whitelist(ip)
            return {'executed': 'remove_whitelist', 'ip': ip}
    except Exception as e:
        print(f"Action parse error: {e}")
    return {}

@app.route('/api/chat/history')
def api_chat_history():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    return jsonify([{**dict(l), 'timestamp': str(l['timestamp'])} for l in get_chat_logs(50)])

# ── DEVICE ROUTES ──
@app.route('/api/register-device', methods=['POST'])
def api_register_device():
    data       = request.get_json()
    username   = data.get('username', '').strip()
    device_id  = data.get('device_id', '').strip()
    public_key = data.get('public_key', '').strip()
    label      = data.get('label', 'Unknown Device')
    client_ip  = request.remote_addr

    if not username or not device_id or not public_key:
        return jsonify({'error': 'missing fields'}), 400
    if not get_user(username):
        return jsonify({'error': 'user not found'}), 404

    register_device(username, device_id, public_key, label)

    # ── Auto-whitelist the IP on registration — Node 3 now has real work ──
    add_to_whitelist(client_ip, f'{username} ({label[:30]})')
    print(f"Auto-whitelisted {client_ip} for '{username}'")

    if username == 'admin':
        approve_device(device_id)
        return jsonify({'status': 'approved'})

    pending = len(get_pending_devices())
    socketio.emit('device_pending', {'username': username, 'device_id': device_id, 'label': label, 'pending_count': pending})
    return jsonify({'status': 'pending'})

@app.route('/api/update-ip', methods=['POST'])
def api_update_ip():
    """
    Lets a user update their whitelisted IP when it changes.
    Requires valid ECDSA device signature — only the real device owner can do this.
    No active session required (they may be locked out due to IP change).
    """
    data             = request.get_json()
    username         = data.get('username', '').strip()
    device_id        = data.get('device_id', '').strip()
    device_signature = data.get('device_signature', '')
    device_message   = data.get('device_message', '')
    client_ip        = request.remote_addr

    if not all([username, device_id, device_signature, device_message]):
        return jsonify({'error': 'missing fields'}), 400

    # Verify device signature before allowing IP update
    verify_payload = {
        'username': username, 'device_id': device_id,
        'device_signature': device_signature, 'device_message': device_message
    }
    if node4_device_signature(verify_payload) != 'PASS':
        add_log(username, client_ip, 'DENIED', 'IP update — invalid device signature')
        return jsonify({'error': 'invalid device signature'}), 403

    # Valid signature — update their IP in whitelist
    device = get_device(device_id)
    label = device['label'] if device else 'Updated device'
    add_to_whitelist(client_ip, f'{username} ({label[:30]})')
    add_log(username, client_ip, 'GRANTED', 'IP updated via device signature')
    print(f"IP updated: '{username}' → {client_ip} whitelisted")
    return jsonify({'success': True, 'new_ip': client_ip})

@app.route('/api/device-status')
def api_device_status():
    device_id = request.args.get('device_id', '')
    if not device_id: return jsonify({'status': 'unknown'})
    device = get_device(device_id)
    if not device: return jsonify({'status': 'not_registered'})
    return jsonify({'status': device['status'], 'username': device['username'], 'label': device['label']})

@app.route('/api/devices')
def api_devices():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    result = []
    for d in get_all_devices():
        row = dict(d)
        row.pop('public_key', None)
        if row.get('created_at'): row['created_at'] = str(row['created_at'])
        if row.get('approved_at'): row['approved_at'] = str(row['approved_at'])
        result.append(row)
    return jsonify(result)

@app.route('/api/devices/approve', methods=['POST'])
def api_device_approve():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    approve_device(data['device_id'])
    socketio.emit('device_approved', {'device_id': data['device_id']})
    return jsonify({'success': True})

@app.route('/api/devices/reject', methods=['POST'])
def api_device_reject():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    reject_device(request.get_json()['device_id'])
    return jsonify({'success': True})

@app.route('/api/devices/delete', methods=['POST'])
def api_device_delete():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    delete_device(request.get_json()['device_id'])
    return jsonify({'success': True})

# ── MAIN ──
if __name__ == '__main__':
    print("Starting NETAD Security System (inline nodes)...")
    threading.Thread(target=token_cleanup_worker, daemon=True).start()
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    socketio.run(app, host=host, port=port, debug=False)
