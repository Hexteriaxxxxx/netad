# main.py — NETAD Security System (Railway-compatible, single-process nodes)

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, Response
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix
from block import Block
from database import (
    add_log, get_logs, get_logs_today, get_sessions, delete_session,
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
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', 'http://localhost:5000')
if ALLOWED_ORIGIN == '*':
    raise RuntimeError("ALLOWED_ORIGIN=* is not allowed.")
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGIN)

# ── SECURITY HEADERS ──
@app.after_request
def security_headers(response):
    response.headers['X-Frame-Options']       = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection']      = '1; mode=block'
    response.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']     = 'camera=(), microphone=(), geolocation=()'
    return response

@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    print(f"Unhandled error: {traceback.format_exc()}")
    return jsonify({'error': 'An internal error occurred.'}), 500

@socketio.on('connect')
def on_socketio_connect():
    pass

@socketio.on('subscribe_dashboard')
def on_subscribe_dashboard():
    if 'user' not in session:
        return False

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
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    if not CAMERA_URLS.get(cam_id): return jsonify({'error': f'CAMERA_{cam_id}_URL not configured'}), 503
    if not is_consensus_granted(): return jsonify({'error': 'consensus not met'}), 403
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
    if not username or not password: return 'FAIL'
    try:
        user = get_user(username)
        if not user: return 'FAIL'
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
    if not token: return 'FAIL'
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
        if token not in _csrf_tokens: return False
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
        time.sleep(120)

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
    if 'user' not in session: return redirect('/logout')
    return render_template('dashboard.html', user=session.get('user', 'admin'))

@app.route('/logout')
def logout():
    user = session.get('user')
    if user: delete_session(user)
    session.clear()
    set_consensus_state(False)
    return redirect('/')

# ── PUBLIC RATE LIMITER ──
_public_rate: dict = {}
_public_rate_lock = threading.Lock()

def public_rate_ok(ip: str, max_per_min: int = 15) -> bool:
    now = time.time()
    with _public_rate_lock:
        _public_rate.setdefault(ip, [])
        _public_rate[ip] = [t for t in _public_rate[ip] if now - t < 60]
        if len(_public_rate[ip]) >= max_per_min: return False
        _public_rate[ip].append(now)
        return True

@app.route('/api/csrf')
def get_csrf():
    if not public_rate_ok(request.remote_addr): return jsonify({'error': 'rate limited'}), 429
    return jsonify({'csrf_token': generate_csrf()})

@app.route('/api/token')
def get_token():
    if not public_rate_ok(request.remote_addr): return jsonify({'error': 'rate limited'}), 429
    return jsonify({'token': secrets.token_hex(32)})

# ── LOGIN ──
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data: return jsonify({'granted': False, 'error': 'invalid request'})
    username      = data.get('username', '').strip()[:50]
    password      = data.get('password', '')[:128]
    csrf_token    = data.get('csrf_token', '')[:128]
    session_token = data.get('session_token', '')[:128] or secrets.token_hex(32)
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
        'username': username, 'password': password, 'ip': client_ip,
        'timestamp': block.timestamp, 'hash': block.hash, 'signature': signature,
        'session_token': session_token,
        'device_id': data.get('device_id', ''),
        'device_signature': data.get('device_signature', ''),
        'device_message': data.get('device_message', ''),
    }
    result, votes, steps = run_consensus(payload)
    granted = result == 'GRANTED'
    add_log(username, client_ip, result)
    if granted:
        user_data = get_user(username)
        role = user_data['role'] if user_data else 'Member'
        sess_token = secrets.token_hex(32)
        delete_session(username)
        create_session(username, client_ip, role, sess_token)
        session['user'] = username
        session['token'] = sess_token
        set_consensus_state(True)
        socketio.emit('camera_access', {'accessible': True, 'reason': '6/6 consensus granted'})
    socketio.emit('login_attempt', {'username': username, 'ip': client_ip, 'result': result, 'votes': votes})
    return jsonify({'granted': granted, 'user': username, 'error': '' if granted else 'authentication failed', 'steps': steps, 'votes': votes})

@app.route('/api/node-status')
def node_status():
    try:
        from database import get_db
        with get_db() as conn:
            conn.cursor().execute('SELECT 1')
        db_ok = True
    except Exception:
        db_ok = False
    return jsonify({'password': db_ok, 'timestamp': True, 'ip_whitelist': db_ok, 'digital_sig': True, 'session_token': db_ok, 'rate_limit': db_ok})

@app.route('/api/logs')
def api_logs():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    return jsonify([{**dict(l), 'timestamp': str(l['timestamp'])} for l in get_logs_today(50)])

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

@app.route('/api/blacklist/forgive', methods=['POST'])
def api_blacklist_forgive():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    ip = request.get_json()['ip']
    forgive_ip(ip); clear_rate_limit(ip); log_admin('forgive_ip', ip)
    return jsonify({'success': True})

@app.route('/api/clear-rate-limit', methods=['POST'])
def api_clear_rate_limit():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    ip = request.get_json().get('ip', '')
    if not ip: return jsonify({'error': 'missing ip'}), 400
    clear_rate_limit(ip)
    socketio.emit('guard_action', {'action': 'clear_rate_limit', 'ip': ip})
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
    log_admin('kick_session', data['username'])
    return jsonify({'success': True})

@app.route('/api/session/heartbeat', methods=['POST'])
def api_session_heartbeat():
    username = request.get_json().get('username', '')
    update_session_heartbeat(username)
    active = get_sessions()
    still_valid = any(s['username'] == username for s in active)
    if not still_valid:
        session.clear()
        set_consensus_state(False)
        return jsonify({'ok': False, 'kicked': True})
    return jsonify({'ok': True})

@app.route('/api/ai-logs')
def api_ai_logs():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    return jsonify([{**dict(l), 'timestamp': str(l['timestamp'])} for l in get_ai_logs(20)])

# ══════════════════════════════════════════════════
# GUARD AI — tools + chat
# ══════════════════════════════════════════════════

# NOTE: kick_session is included but heavily restricted via system prompt.
GUARD_TOOLS = [
    {'type': 'function', 'function': {
        'name': 'block_ip',
        'description': 'Block an IP address and add it to the blacklist for 30 minutes.',
        'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}
    }},
    {'type': 'function', 'function': {
        'name': 'forgive_ip',
        'description': 'Remove an IP from the blacklist and clear its failed login history.',
        'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}
    }},
    {'type': 'function', 'function': {
        'name': 'clear_rate_limit',
        'description': 'Clear failed login attempts for an IP so they can try again.',
        'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}
    }},
    {'type': 'function', 'function': {
        'name': 'add_whitelist',
        'description': 'Add an IP to the whitelist.',
        'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}, 'label': {'type': 'string'}}, 'required': ['ip']}
    }},
    {'type': 'function', 'function': {
        'name': 'remove_whitelist',
        'description': 'Remove an IP from the whitelist.',
        'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}
    }},
    {'type': 'function', 'function': {
        'name': 'kick_session',
        'description': 'Force logout a specific user by their exact username. ONLY call this when the user explicitly says to kick a specific named person.',
        'parameters': {'type': 'object', 'properties': {'username': {'type': 'string', 'description': 'The exact username to kick'}}, 'required': ['username']}
    }},
]

def _run_tool(tool_name: str, args: dict) -> str:
    try:
        if tool_name == 'block_ip':
            ip = args['ip']; add_to_blacklist(ip, 'temporary', 1800); socketio.emit('guard_action', {'action': 'block_ip', 'ip': ip}); return f"Blocked {ip} for 30 minutes."
        elif tool_name == 'forgive_ip':
            ip = args['ip']; forgive_ip(ip); clear_rate_limit(ip); socketio.emit('guard_action', {'action': 'forgive_ip', 'ip': ip}); return f"Forgiven {ip}."
        elif tool_name == 'clear_rate_limit':
            ip = args['ip']; clear_rate_limit(ip); socketio.emit('guard_action', {'action': 'clear_rate_limit', 'ip': ip}); return f"Rate limit cleared for {ip}."
        elif tool_name == 'add_whitelist':
            ip = args['ip']; label = args.get('label', 'Guard approved'); add_to_whitelist(ip, label); socketio.emit('guard_action', {'action': 'add_whitelist', 'ip': ip}); return f"Added {ip} to whitelist."
        elif tool_name == 'remove_whitelist':
            ip = args['ip']; remove_from_whitelist(ip); socketio.emit('guard_action', {'action': 'remove_whitelist', 'ip': ip}); return f"Removed {ip} from whitelist."
        elif tool_name == 'kick_session':
            username = args['username']; delete_session(username); socketio.emit('session_kicked', {'username': username}); log_admin('kick_session', username); return f"Kicked {username} — session terminated."
        else:
            return f"Unknown tool: {tool_name}"
    except Exception as e:
        return f"Tool error: {e}"

def mask_ip(ip: str) -> str:
    parts = ip.split('.')
    return f"x.x.x.{parts[-1]}" if len(parts) == 4 else 'x.x.x.x'

def log_admin(action: str, target: str):
    admin = session.get('user', 'system')
    ip = request.remote_addr if request else 'internal'
    add_log(admin, ip, 'ADMIN', f'{action}: {target}')

def _get_system_context() -> str:
    try:
        logs     = get_logs(10)
        ai_logs  = get_ai_logs(5)
        sessions = get_sessions()
        bl       = get_blacklist()
        wl       = get_whitelist()
        pending  = get_pending_devices()
        online   = [s for s in sessions if s.get('online')]
        ctx  = "=== LIVE NETAD SYSTEM STATE ===\n"
        ctx += f"Camera access: {'OPEN' if is_consensus_granted() else 'LOCKED'}\n"
        ctx += f"All 6 nodes: ONLINE (always active)\n"
        ctx += f"Pending device approvals: {len(pending)}\n"
        ctx += f"Active sessions ({len(online)} online):\n"
        for s in sessions:
            status = 'ONLINE' if s.get('online') else 'OFFLINE'
            ctx += f"  - {s.get('username','')} | {status} | ip={mask_ip(str(s.get('ip','')))} | role={s.get('role','')}\n"
        ctx += "\nRecent logs:\n"
        for l in logs:
            ctx += f"  [{l.get('timestamp','')}] {l.get('result','')} — user={l.get('username','')} ip={mask_ip(str(l.get('ip','')))} reason={l.get('reason','')}\n"
        ctx += "\nAI flags:\n"
        for a in ai_logs:
            ctx += f"  ip={mask_ip(str(a.get('ip','')))} user={a.get('username','')} score={a.get('score','')} flagged={a.get('flagged','')}\n"
        ctx += f"\nBlacklisted: {len(bl)} IPs\nWhitelisted: {len(wl)} IPs\n"
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

    system_prompt = (
        "You are NETAD Guard, an AI security officer for the NETAD security system.\n"
        "You have real-time access to logs, sessions, devices, blacklist, and whitelist.\n"
        "You speak professionally and concisely.\n\n"
        "STRICT RULES:\n"
        "- For ANY informational question (who is online, show logs, show sessions, etc.) — just answer, NEVER call a tool.\n"
        "- Only call kick_session when the user EXPLICITLY says to kick a SPECIFIC person by name. Example: 'kick kevin', 'remove nico'. NEVER call kick_session just because you see a list of users.\n"
        "- Only call block_ip when user explicitly says 'block [ip]'.\n"
        "- Only call other tools when explicitly requested.\n"
        "- When in doubt — describe, do not act.\n\n"
        + _get_system_context()
    )

    messages = [{'role': 'system', 'content': system_prompt}]
    for msg in chat_history[-16:]:
        if msg.get('role') == 'system': continue
        messages.append({'role': msg.get('role', 'user'), 'content': msg.get('message', '')})
    messages.append({'role': 'user', 'content': user_message})

    try:
        from groq import Groq
        client = Groq(api_key=groq_api_key)
        executed_actions = []

        response = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            messages=messages,
            tools=GUARD_TOOLS,
            tool_choice='auto',
            max_tokens=1024,
            temperature=0.3
        )
        msg_obj = response.choices[0].message

        if msg_obj.tool_calls:
            messages.append({
                'role': 'assistant',
                'content': msg_obj.content or '',
                'tool_calls': [{'id': tc.id, 'type': 'function', 'function': {'name': tc.function.name, 'arguments': tc.function.arguments}} for tc in msg_obj.tool_calls]
            })
            for tc in msg_obj.tool_calls:
                args = json.loads(tc.function.arguments)
                result = _run_tool(tc.function.name, args)
                executed_actions.append({'tool': tc.function.name, 'args': args, 'result': result})
                messages.append({'role': 'tool', 'tool_call_id': tc.id, 'content': result})
            followup = client.chat.completions.create(model='llama-3.3-70b-versatile', messages=messages, max_tokens=512, temperature=0.3)
            reply = followup.choices[0].message.content.strip()
        else:
            reply = msg_obj.content.strip() if msg_obj.content else 'No response.'

        add_chat_log('assistant', reply)
        socketio.emit('chat_message', {'role': 'assistant', 'message': reply})
        return jsonify({'reply': reply, 'action_result': executed_actions})

    except Exception as e:
        return jsonify({'reply': f'Guard unavailable: {e}'})

@app.route('/api/chat/history')
def api_chat_history():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    return jsonify([{**dict(l), 'timestamp': str(l['timestamp'])} for l in get_chat_logs(50)])

# ── DEVICE REGISTRATION RATE LIMIT ──
_device_reg_attempts: dict = {}
_device_reg_lock = threading.Lock()

def check_device_reg_rate(ip: str, max_attempts: int = 3, window: int = 3600) -> bool:
    now = time.time()
    with _device_reg_lock:
        _device_reg_attempts.setdefault(ip, [])
        _device_reg_attempts[ip] = [t for t in _device_reg_attempts[ip] if now - t < window]
        if len(_device_reg_attempts[ip]) >= max_attempts: return False
        _device_reg_attempts[ip].append(now)
        return True

# ── DEVICE ROUTES ──
@app.route('/api/register-device', methods=['POST'])
def api_register_device():
    data       = request.get_json()
    username   = data.get('username', '').strip()
    device_id  = data.get('device_id', '').strip()
    public_key = data.get('public_key', '').strip()
    label      = data.get('label', 'Unknown Device')
    client_ip  = request.remote_addr
    if not username or not device_id or not public_key: return jsonify({'error': 'registration failed'}), 400
    if not check_device_reg_rate(client_ip): return jsonify({'error': 'registration failed'}), 429
    if not get_user(username): return jsonify({'error': 'registration failed'}), 400
    register_device(username, device_id, public_key, label, registered_ip=client_ip)
    if username == 'admin':
        approve_device(device_id)
        add_to_whitelist(client_ip, f'admin ({label[:30]})')
        return jsonify({'status': 'approved'})
    pending = len(get_pending_devices())
    socketio.emit('device_pending', {'username': username, 'device_id': device_id, 'label': label, 'pending_count': pending})
    return jsonify({'status': 'pending'})

@app.route('/api/update-ip', methods=['POST'])
def api_update_ip():
    data             = request.get_json()
    username         = data.get('username', '').strip()
    device_id        = data.get('device_id', '').strip()
    device_signature = data.get('device_signature', '')
    device_message   = data.get('device_message', '')
    client_ip        = request.remote_addr
    if not all([username, device_id, device_signature, device_message]): return jsonify({'error': 'request failed'}), 400
    if not check_device_reg_rate(client_ip, max_attempts=5, window=3600): return jsonify({'error': 'request failed'}), 429
    verify_payload = {'username': username, 'device_id': device_id, 'device_signature': device_signature, 'device_message': device_message}
    if node4_device_signature(verify_payload) != 'PASS':
        add_log(username, client_ip, 'DENIED', 'IP update — invalid device signature')
        return jsonify({'error': 'invalid device signature'}), 403
    device = get_device(device_id)
    label = device['label'] if device else 'Updated device'
    add_to_whitelist(client_ip, f'{username} ({label[:30]})')
    add_log(username, client_ip, 'GRANTED', 'IP updated via device signature')
    return jsonify({'success': True, 'new_ip': client_ip})

@app.route('/api/device-status')
def api_device_status():
    device_id = request.args.get('device_id', '')
    if not device_id: return jsonify({'status': 'unknown'})
    device = get_device(device_id)
    if not device: return jsonify({'status': 'not_registered'})
    return jsonify({'status': device['status']})

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
    device_id = data['device_id']
    approve_device(device_id)
    device = get_device(device_id)
    if device and device.get('registered_ip'):
        add_to_whitelist(device['registered_ip'], f"{device['username']} ({device['label'][:30]})")
    socketio.emit('device_approved', {'device_id': device_id})
    log_admin('approve_device', device_id)
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
