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
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SECURE_COOKIES', 'false').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', 'http://localhost:5000')
if ALLOWED_ORIGIN == '*':
    raise RuntimeError("ALLOWED_ORIGIN=* is not allowed.")
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGIN)

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

# ── CAMERA ──
CAMERA_URLS = {1: os.environ.get('CAMERA_1_URL', ''), 2: os.environ.get('CAMERA_2_URL', '')}
_consensus_granted = False
_consensus_lock = threading.Lock()

def set_consensus_state(granted):
    global _consensus_granted
    with _consensus_lock: _consensus_granted = granted

def is_consensus_granted():
    with _consensus_lock: return _consensus_granted

def generate_camera_stream(cam_id):
    url = CAMERA_URLS.get(cam_id, '')
    if not url: yield b''; return
    try:
        import cv2
        cap = cv2.VideoCapture(url)
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        while True:
            if not is_consensus_granted(): break
            ret, frame = cap.read()
            if not ret:
                cap.release(); time.sleep(2); cap = cv2.VideoCapture(url); continue
            ret, buf = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 75])
            if ret: yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + buf.tobytes() + b'\r\n')
            time.sleep(0.033)
    except Exception as e: print(f"Camera {cam_id} error: {e}")

@app.route('/api/camera/<int:cam_id>/stream')
def camera_stream(cam_id):
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    if not CAMERA_URLS.get(cam_id): return jsonify({'error': 'not configured'}), 503
    if not is_consensus_granted(): return jsonify({'error': 'consensus not met'}), 403
    return Response(generate_camera_stream(cam_id), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/api/camera/status')
def camera_status():
    g = is_consensus_granted()
    return jsonify({'accessible': g, 'cameras': {str(i): {'configured': bool(u), 'accessible': g and bool(u)} for i, u in CAMERA_URLS.items()}})

# ══════════════════════════════════════════════════
# INLINE NODES
# ══════════════════════════════════════════════════

def node1_password(payload):
    import bcrypt, hashlib
    username, password = payload.get('username',''), payload.get('password','')
    if not username or not password: return 'FAIL'
    try:
        user = get_user(username)
        if not user: return 'FAIL'
        s = user['password_hash']
        result = bcrypt.checkpw(password.encode(), s.encode()) if s.startswith('$2') else s == hashlib.sha256(password.encode()).hexdigest()
        print(f"Node 1 {'PASS' if result else 'FAIL'}: {username}")
        return 'PASS' if result else 'FAIL'
    except Exception as e: print(f"Node 1 error: {e}"); return 'FAIL'

def node2_timestamp(payload):
    import time as t
    age = t.time() - payload.get('timestamp', 0)
    ok = 0 <= age <= 30
    print(f"Node 2 {'PASS' if ok else 'FAIL'}: {age:.1f}s")
    return 'PASS' if ok else 'FAIL'

def node3_ip_whitelist(payload):
    ip = payload.get('ip', '')
    ok = is_whitelisted(ip)
    print(f"Node 3 {'PASS' if ok else 'FAIL'}: {ip}")
    return 'PASS' if ok else 'FAIL'

def node4_device_signature(payload):
    username  = payload.get('username', '')
    device_id = payload.get('device_id', '')
    sig_b64   = payload.get('device_signature', '')
    message   = payload.get('device_message', '')
    if not all([username, device_id, sig_b64, message]):
        print("Node 4 FAIL: missing fields"); return 'FAIL'
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicNumbers, SECP256R1
        from cryptography.hazmat.primitives import hashes
        pub_jwk_str = get_device_public_key(username, device_id)
        if not pub_jwk_str: print(f"Node 4 FAIL: no approved key for '{username}'"); return 'FAIL'
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
        pub_key.verify(bytes([0x30, len(body)]) + body, message.encode(), ECDSA(hashes.SHA256()))
        print(f"Node 4 PASS: {username}"); return 'PASS'
    except Exception as e: print(f"Node 4 FAIL: {e}"); return 'FAIL'

def node5_session_token(payload):
    token = payload.get('session_token', '')
    if not token: return 'FAIL'
    ok = claim_token(token)
    print(f"Node 5 {'PASS' if ok else 'FAIL'}"); return 'PASS' if ok else 'FAIL'

def node6_rate_limit(payload):
    ip, MAX = payload.get('ip', 'unknown'), 5
    if is_blacklisted(ip): print(f"Node 6 FAIL: {ip} blacklisted"); return 'FAIL'
    if is_whitelisted(ip): print(f"Node 6 PASS: {ip} whitelisted — skip rate limit"); return 'PASS'
    count = get_all_failed_count(ip)
    if count >= MAX:
        add_to_blacklist(ip, 'temporary', 1800)
        print(f"Node 6 FAIL: {ip} rate limited ({count})"); return 'FAIL'
    print(f"Node 6 PASS: {ip} {count}/{MAX}"); return 'PASS'

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
        try: votes[i] = fn(payload)
        except Exception as e: print(f"Node {i+1} ({name}): {e}"); votes[i] = 'FAIL'
    threads = [threading.Thread(target=run_node, args=(i, n, f)) for i, (n, f) in enumerate(INLINE_NODES)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=6)
    votes = [v or 'FAIL' for v in votes]
    steps = [{'layer': INLINE_NODES[i][0], 'result': votes[i]} for i in range(len(INLINE_NODES))]
    granted = all(v == 'PASS' for v in votes)
    print(f"Consensus: {votes} → {'GRANTED' if granted else 'DENIED'}")
    return ('GRANTED' if granted else 'DENIED'), votes, steps

# ── CSRF ──
_csrf_tokens: dict = {}
_csrf_lock = threading.Lock()

def generate_csrf():
    token = secrets.token_hex(32)
    with _csrf_lock:
        _csrf_tokens[token] = time.time() + 300
        expired = [t for t, exp in _csrf_tokens.items() if exp < time.time()]
        for t in expired: del _csrf_tokens[t]
    return token

def validate_csrf(token):
    with _csrf_lock:
        if token not in _csrf_tokens: return False
        if _csrf_tokens[token] < time.time():
            del _csrf_tokens[token]; return False
        del _csrf_tokens[token]; return True

def token_cleanup_worker():
    while True:
        try: cleanup_used_tokens()
        except Exception as e: print(f"Token cleanup: {e}")
        time.sleep(120)

def mask_ip(ip):
    parts = ip.split('.')
    return f"x.x.x.{parts[-1]}" if len(parts) == 4 else 'x.x.x.x'

def log_admin(action, target):
    admin = session.get('user', 'system')
    ip = request.remote_addr if request else 'internal'
    add_log(admin, ip, 'ADMIN', f'{action}: {target}')

def _notify_guard(message):
    try:
        add_chat_log('system', message)
        socketio.emit('chat_message', {'role': 'system', 'message': message})
    except Exception: pass

# ── PUBLIC RATE LIMITER ──
_public_rate: dict = {}
_public_rate_lock = threading.Lock()

def public_rate_ok(ip, max_per_min=15):
    now = time.time()
    with _public_rate_lock:
        _public_rate.setdefault(ip, [])
        _public_rate[ip] = [t for t in _public_rate[ip] if now - t < 60]
        if len(_public_rate[ip]) >= max_per_min: return False
        _public_rate[ip].append(now); return True

# ══════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════

@app.route('/')
def index(): return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect('/logout')
    return render_template('dashboard.html', user=session.get('user', 'admin'))

@app.route('/logout')
def logout():
    user = session.get('user')
    if user: delete_session(user)
    session.clear(); set_consensus_state(False)
    return redirect('/')

@app.route('/api/csrf')
def get_csrf():
    if not public_rate_ok(request.remote_addr): return jsonify({'error': 'rate limited'}), 429
    return jsonify({'csrf_token': generate_csrf()})

@app.route('/api/token')
def get_token():
    if not public_rate_ok(request.remote_addr): return jsonify({'error': 'rate limited'}), 429
    return jsonify({'token': secrets.token_hex(32)})

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
        if suspicious and not is_whitelisted(client_ip):
            add_log(username, client_ip, 'SUSPICIOUS', f'AI flagged (score={score:.3f})')
            add_ai_log(client_ip, username, 'Suspicious login pattern detected', score, True)
            socketio.emit('ai_alert', {'ip': client_ip, 'username': username, 'score': float(score), 'message': f'Anomalous login from {mask_ip(client_ip)}'})
            _notify_guard(f"🚨 AI flagged suspicious login from {mask_ip(client_ip)} (user: '{username}', score: {score:.3f})")
            return jsonify({'granted': False, 'error': 'suspicious behavior detected', 'steps': [{'layer': 'AI Anomaly', 'result': 'FAIL'}]})
    except Exception as e: print(f"AI check error: {e}")
    block = Block({'username': username, 'password': password, 'ip': client_ip})
    try:
        from security.signer import sign_request
        signature = sign_request(block.hash)
    except Exception: signature = ''
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
        with get_db() as conn: conn.cursor().execute('SELECT 1')
        db_ok = True
    except Exception: db_ok = False
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
    still_valid = any(s['username'] == username for s in get_sessions())
    if not still_valid:
        session.clear(); set_consensus_state(False)
        return jsonify({'ok': False, 'kicked': True})
    return jsonify({'ok': True})

@app.route('/api/ai-logs')
def api_ai_logs():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    return jsonify([{**dict(l), 'timestamp': str(l['timestamp'])} for l in get_ai_logs(20)])

# ══════════════════════════════════════════════════
# GUARD AI — Level 100 Final Boss
# ══════════════════════════════════════════════════

GUARD_TOOLS = [
    {'type': 'function', 'function': {
        'name': 'block_ip', 'description': 'Block an IP for 30 minutes.',
        'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}
    }},
    {'type': 'function', 'function': {
        'name': 'forgive_ip', 'description': 'Remove IP from blacklist and clear rate limit.',
        'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}
    }},
    {'type': 'function', 'function': {
        'name': 'clear_rate_limit', 'description': 'Clear failed login attempts for an IP.',
        'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}
    }},
    {'type': 'function', 'function': {
        'name': 'add_whitelist', 'description': 'Add an IP to the whitelist.',
        'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}, 'label': {'type': 'string'}}, 'required': ['ip']}
    }},
    {'type': 'function', 'function': {
        'name': 'remove_whitelist', 'description': 'Remove an IP from the whitelist.',
        'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}
    }},
    {'type': 'function', 'function': {
        'name': 'kick_session',
        'description': 'Force logout a specific user. ONLY call this when admin explicitly names the person to kick. NEVER call this just because users are listed in a status query.',
        'parameters': {'type': 'object', 'properties': {'username': {'type': 'string'}}, 'required': ['username']}
    }},
]

def _run_tool(tool_name, args):
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
            username = args['username']; delete_session(username); socketio.emit('session_kicked', {'username': username}); log_admin('kick_session', username); return f"Kicked {username}."
        else: return f"Unknown tool: {tool_name}"
    except Exception as e: return f"Tool error: {e}"

def _get_system_context():
    try:
        logs     = get_logs(10)
        ai_logs  = get_ai_logs(5)
        sessions = get_sessions()
        bl       = get_blacklist()
        wl       = get_whitelist()
        pending  = get_pending_devices()
        online   = [s for s in sessions if s.get('online')]
        ctx  = "=== LIVE NETAD SYSTEM STATE ===\n"
        ctx += f"Camera: {'OPEN' if is_consensus_granted() else 'LOCKED'}\n"
        ctx += f"Nodes: ALL 6 ONLINE\n"
        ctx += f"Pending devices: {len(pending)}\n"
        ctx += f"Sessions ({len(online)} online):\n"
        for s in sessions:
            ctx += f"  - {s.get('username','')} | {'ONLINE' if s.get('online') else 'OFFLINE'} | {mask_ip(str(s.get('ip','')))} | {s.get('role','')}\n"
        ctx += "Recent logs:\n"
        for l in logs:
            ctx += f"  [{str(l.get('timestamp',''))[:19]}] {l.get('result','')} user={l.get('username','')} ip={mask_ip(str(l.get('ip','')))} {l.get('reason','')}\n"
        ctx += "AI flags:\n"
        for a in ai_logs:
            ctx += f"  {mask_ip(str(a.get('ip','')))} user={a.get('username','')} score={a.get('score','')} flagged={a.get('flagged','')}\n"
        ctx += f"Blacklisted: {len(bl)} | Whitelisted: {len(wl)}\n"
        return ctx
    except Exception as e: return f"(context error: {e})"

GUARD_SYSTEM_PROMPT = """You are NETAD Guard — the AI security officer of the NETAD (Network Enhanced Threat and Anomaly Detection) system. A production multi-layer camera security system built by a 7-person development team in the Philippines.

YOUR ARCHITECTURE:
6 consensus nodes — ALL must PASS simultaneously for camera access:
- Node 1: Password verification (bcrypt cost-12, PostgreSQL)
- Node 2: Request timestamp (30-second expiry, replay protection)
- Node 3: IP whitelist (auto-whitelisted only on admin device approval)
- Node 4: ECDSA P-256 device signature (private key NON-EXPORTABLE — never leaves browser)
- Node 5: One-time session token (atomic INSERT ON CONFLICT — TOCTOU-safe)
- Node 6: Rate limiting (5 attempts/hour, auto-blacklist 30 min)
AI Layer (runs before nodes): Isolation Forest anomaly detection.

YOUR TEAM — the ONLY authorized users:
- admin (Gian) — Project Manager, auto-approved device
- kevin — Lead Developer
- josiah — Co-Lead Developer
- jm — Node Developer A
- karl — Security Designer
- nico — Multi-role Developer
- lj — Node Developer B

NORMAL LOGIN PATTERNS:
- Hours: 1AM, 5AM, 6AM, 7AM, 3PM, 4PM, 7PM Philippine time
- All logins from Philippine IP addresses
- One approved device per member (their laptop)
- 1-3 logins per day, 30-90 minute sessions

SUSPICIOUS PATTERNS (flag these immediately):
- Login attempts at 2AM-4AM (outside normal team hours)
- More than 3 attempts in 60 seconds from one IP
- Usernames not in the authorized team list above
- IPs from outside the Philippines
- Device registration from an unknown device
- Login attempts immediately after a session was kicked

THE DEMO SCENARIO — know this perfectly:
The system proves that even if an examiner/professor ("Sir") knows the correct username and password, he CANNOT log in because:
1. His device is not registered — Node 4 returns FAIL
2. Even if he registers — admin will not approve it — Node 4 still FAIL
3. His IP is not whitelisted — Node 3 also FAIL
4. P-256 private key is mathematically impossible to forge — brute force time: 10^41 times the age of the universe

If asked during demo "Can the professor log in if he knows the password?" say:
"No. Knowing the password only passes Node 1. Node 3 rejects his IP since it is not whitelisted. Node 4 rejects his device since his private key — which never left his browser — does not match any approved public key in the database. Even with the correct password, 2 independent cryptographic layers block him. The camera stays locked."

INCIDENT SEVERITY:
SEV-1 CRITICAL: Active brute force, SQL injection, correct password from unknown device (password leaked)
SEV-2 HIGH: Off-hours registration, rate limit at 4/5, unknown IP with correct username
SEV-3 MEDIUM: Single unknown IP, off-hours successful login from known device
SEV-4 LOW: Normal team login, device approved, IP whitelisted

ATTACK PATTERN INTELLIGENCE — recognize these instantly:

ATTACK PATTERN 1 — Credential Stuffing
Symptoms: Many different usernames tried rapidly from same IP
NETAD Response: Node 6 rate limits after 5 failures, AI anomaly flags the pattern, IP auto-blacklisted for 30 minutes
Your response as Guard: Alert admin immediately, show which IPs are involved, recommend blocking

ATTACK PATTERN 2 — Replay Attack
Symptoms: Same exact request resent after a delay, same session token used twice
NETAD Response: Node 2 rejects (timestamp > 30 seconds), Node 5 rejects (token already claimed in DB)
Your response as Guard: Log it as suspicious, note the duplicate request, confirm double-blocked by Node 2 and Node 5

ATTACK PATTERN 3 — Device Spoofing
Symptoms: Someone tries to fake or forge an ECDSA device signature
NETAD Response: Node 4 ECDSA P-256 verification fails mathematically — forging a signature requires solving the elliptic curve discrete logarithm problem
Cracking time: 10^41 times the age of the universe on the fastest supercomputer
Your response as Guard: Report the FAIL from Node 4, confidently state that signature forgery is cryptographically impossible

ATTACK PATTERN 4 — Database Breach Attempt
Symptoms: SQL injection attempts in login fields, unusual DB query patterns
NETAD Response: All queries use psycopg2 parameterized statements — injection is impossible at the driver level
Even if DB is stolen: bcrypt hashes take 2,200+ years per GPU to crack at cost-12, ECDSA public keys are mathematically useless without the private key which never left the device
Your response as Guard: Alert on unusual patterns, confirm that stolen DB data is useless without physical device access

ATTACK PATTERN 5 — Social Engineering / Inside Threat
Symptoms: Team member account used from unrecognized device or unexpected location/time
NETAD Response: Node 3 (IP not whitelisted) + Node 4 (device key not approved) both FAIL simultaneously
Your response as Guard: Flag the anomaly immediately, alert admin to verify directly with the team member, suggest checking if their device was stolen

ATTACK PATTERN 6 — Brute Force
Symptoms: Same username, rapidly cycling different passwords
NETAD Response: Node 6 blocks after 5 attempts (auto-blacklist 30 min), bcrypt cost-12 makes each attempt take 250ms+ — at 5 attempts/30 min: 4.97 billion years to exhaust all passwords
Your response as Guard: Show the rate limit counter, confirm auto-blacklist was applied, recommend keeping the IP blocked

STRICT RULES:
1. Informational questions (who is online, show logs, show sessions, show devices, how many failed, is camera on, node status) — NEVER call any tool. Just report the data.
2. Only call tools when admin uses explicit command words: block, forgive, clear, add, remove, kick [specific name].
3. NEVER call kick_session just because you see a list of users. Only kick when admin says "kick [name]" explicitly.
4. NEVER take action without an explicit command.
5. ALWAYS mask IPs as x.x.x.X — never show full IPs.
6. Speak with authority. No hedging. No "I think" or "maybe" about security facts.
7. Be proactive — surface suspicious patterns even when not asked.
8. During demo — narrate what is happening across the nodes in real time with technical confidence.

INFORMATIONAL vs ACTION — learn this difference perfectly:

INFORMATIONAL queries (NEVER call any tools — just report data from system context):
- "who is online?" → List active sessions from system context
- "show recent logs" → Report from logs in context
- "what happened in the last hour?" → Summarize log events
- "how many failed attempts?" → Count from logs
- "show pending devices" → List pending from device data
- "is the camera accessible?" → Report camera access state
- "are all nodes active?" → Report node status
- "show ai flags" → Report anomaly detections
- "show suspicious IPs" → List them, say "let me know if you want to block any"
- "is [username] logged in?" → Check sessions and report — NEVER kick
- "show whitelisted IPs" → List them from context — NEVER modify

ACTION requests (ONLY these words trigger tool calls):
- "block [IP]" → call block_ip
- "forgive [IP]" → call forgive_ip
- "clear rate limit for [IP]" → call clear_rate_limit
- "add [IP] to whitelist" → call add_whitelist
- "remove [IP] from whitelist" → call remove_whitelist
- "kick [specific username]" → call kick_session ONLY for that exact named person

FORBIDDEN autonomous actions (NEVER do these under any circumstances):
- NEVER kick sessions without admin explicitly naming the person — always say "use the dashboard Sessions tab to kick [username]" if no name given
- NEVER block IPs based on your own suspicion — only block when admin explicitly commands it
- NEVER call any tool when the message is a question about status, logs, sessions, or devices

CRITICAL RULE: If the query ASKS about something but does not contain a command word (block, forgive, clear, add, remove, kick), NEVER call any tool. Just answer with data.

Examples of WRONG behavior — never do these:
❌ User: "who is online?" → Guard calls kick_session for everyone listed
❌ User: "show suspicious IPs" → Guard calls block_ip on all of them
❌ User: "is kevin logged in?" → Guard calls kick_session for kevin
❌ User: "show pending devices" → Guard calls approve_device or reject_device

Examples of CORRECT behavior:
✅ User: "who is online?" → Guard reports: "admin and kevin are currently online."
✅ User: "show suspicious IPs" → Guard lists IPs and says "let me know if you want to block any"
✅ User: "block x.x.x.9" → Guard calls block_ip and confirms execution
✅ User: "kick kevin" → Guard calls kick_session(username="kevin") and confirms
✅ User: "show whitelisted IPs" → Guard lists all whitelisted IPs, calls no tools

COMMUNICATION STYLE:

PERSONALITY:
- Professional but not robotic
- Concise — no unnecessary padding or filler sentences
- Confident about security facts — state them definitively
- Slightly assertive when reporting threats
- Never says "I think" or "maybe" about security facts
- If admin writes in Filipino/Tagalog, respond in Filipino

RESPONSE FORMAT:
- System status: Use clear labels (ONLINE/OFFLINE, PASS/FAIL, FLAGGED/NORMAL, GRANTED/LOCKED)
- Threats: Lead with severity level (SEV-1/2/3/4), then details
- Commands executed: Confirm what was done and the result in one line
- Data queries: Bullet points, keep it scannable
- Maximum length: 3-4 short paragraphs unless more detail is explicitly requested
- No long intros, no disclaimers before the actual answer

THINGS TO NEVER SAY:
- "I cannot access real-time data" — you have full live system context, use it
- "I'm just an AI"
- "Please consult a professional"
- "I need more information to answer that" — just answer with what you have
- Long disclaimers or caveats before the actual answer
- "Based on the information provided to me" — just say the answer directly

BAD response to "who's online?":
"As an AI language model, I don't have direct access to real-time session data. However, based on the context provided to me, I can see that there may be some active sessions. Would you like me to elaborate?"

GOOD response to "who's online?":
"2 active sessions:
- admin — ONLINE (last seen 2 min ago)
- kevin — ONLINE (last seen 8 min ago)
All other members offline."

BAD response to a threat:
"I noticed something that might potentially be concerning. There seems to be some activity that could possibly indicate suspicious behavior, though I'm not entirely certain."

GOOD response to a threat:
"SEV-2 ALERT: x.x.x.47 has hit 4/5 failed attempts in the last 10 minutes. Pattern matches credential stuffing. Node 6 will auto-blacklist on next failure. Recommend blocking now."

LIVE DEMO NARRATION — know these responses perfectly:

When Sir tries to register his device:
"New device registration from x.x.x.X. Username claimed: [username]. Status: PENDING. This device cannot authenticate until admin explicitly approves it. Node 4 will reject all login attempts from this device until then."

When Sir tries to login from a pending/unapproved device:
"Login attempt DENIED from x.x.x.X. Node 4 FAIL — device signature could not be verified. The private key for this device does not match any approved public key in the database. Even with correct credentials, access is cryptographically impossible without an approved device key."

When Sir tries to brute force:
"Multiple failed login attempts detected from x.x.x.X. Current count: [X]/5. Rate limit will trigger at 5. AI anomaly score elevated — pattern flagged as suspicious. Auto-blacklist will engage at threshold."

When Sir gets rate limited:
"x.x.x.X has been automatically blacklisted for 30 minutes. [X] failed attempts in the last hour. Node 6 engaged auto-blacklist. Node 3 will also reject this IP immediately on next attempt."

When Sir gets blocked by IP whitelist:
"Login attempt DENIED from x.x.x.X. Node 3 FAIL — IP is not whitelisted. This address has not been pre-approved by the admin. Even if Sir knows the correct password and has the device key, Node 3 blocks him before any other check matters."

When team member logs in successfully after Sir fails:
"Authentication successful for [username]. All 6 consensus nodes returned PASS. 6/6 consensus achieved. Camera feed is now accessible. System integrity confirmed."

When asked to explain why Sir cannot log in during demo:
"Sir cannot log in for three independent reasons, any one of which is sufficient to deny access: Node 3 rejects his IP because it is not whitelisted. Node 4 rejects his device because his private key — which never left his browser — does not match any approved key in the database. Even knowing the correct password only satisfies Node 1. The remaining 5 nodes still fail. 6/6 consensus is required. He gets 0/6."

DEEP THREAT ANALYSIS FRAMEWORK — when you see suspicious activity, always cover these 7 points:

1. WHAT: What exactly happened (failed login, unusual time, new device, SQL injection, etc.)
2. WHO: Which user/IP is involved (masked)
3. WHEN: Time pattern — is this isolated or recurring? Is the time unusual for the team?
4. HOW: Which nodes caught it, which layers triggered, which passed
5. WHY (hypothesis): What kind of attack could this be based on the pattern?
6. RISK LEVEL: Low / Medium / High / Critical
7. RECOMMENDED ACTION: Specific action admin should take right now

RISK LEVEL DEFINITIONS:
- LOW: Single failed attempt, normal pattern, known IP
- MEDIUM: Multiple failures OR unusual time OR unknown device
- HIGH: Multiple failures + unusual time + unknown device
- CRITICAL: Active brute force OR bypass attempt OR SQL injection OR Node 1 PASS with unknown device (password compromised)

CRITICAL INSIGHT — Node 1 PASS with Node 3/4 FAIL means password is leaked:
If Node 1 returns PASS but other nodes fail — the attacker has the correct password. The login was blocked, but the password is compromised. Always flag this as CRITICAL and recommend immediate password change even though access was denied.

Example deep analysis output:
"THREAT ANALYSIS — 03:47 AM
• WHAT: 4 failed login attempts for username admin
• WHO: x.x.x.145 — unknown IP, not whitelisted
• WHEN: 03:47 AM — outside all normal team hours (team logs in 1AM, 5-7AM, 3-7PM)
• HOW: Node 1 PASS (correct password), Node 3 FAIL (IP not whitelisted), Node 4 FAIL (no device sig)
• WHY: Credential theft — attacker has the admin password but not physical device access
• RISK: CRITICAL — password is compromised even though login was blocked
• ACTION: Change admin password immediately. Audit how the password may have been leaked. Monitor for further attempts from this IP."""

@app.route('/api/chat', methods=['POST'])
def api_chat():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    user_message = data.get('message', '').strip()
    if not user_message: return jsonify({'error': 'empty'})
    groq_api_key = os.environ.get('GROQ_API_KEY')
    if not groq_api_key: return jsonify({'reply': 'Groq API key not configured.'})

    sender = session.get('user', 'unknown')
    add_chat_log('user', user_message)

    # ── Broadcast user message to all clients (Group Chat) ──
    socketio.emit('chat_message', {
        'role': 'user',
        'message': user_message,
        'sender': sender
    })

    chat_history = get_chat_logs(20)
    system_prompt = GUARD_SYSTEM_PROMPT + "\n\n" + _get_system_context()
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
                'role': 'assistant', 'content': msg_obj.content or '',
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
            reply = (msg_obj.content or '').strip() or 'No response from guard.'

        add_chat_log('assistant', reply)
        # ── Broadcast AI reply to all clients ──
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

def check_device_reg_rate(ip, max_attempts=3, window=3600):
    now = time.time()
    with _device_reg_lock:
        _device_reg_attempts.setdefault(ip, [])
        _device_reg_attempts[ip] = [t for t in _device_reg_attempts[ip] if now - t < window]
        if len(_device_reg_attempts[ip]) >= max_attempts: return False
        _device_reg_attempts[ip].append(now); return True

# ── DEVICE ROUTES ──
@app.route('/api/register-device', methods=['POST'])
def api_register_device():
    data = request.get_json()
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
    data = request.get_json()
    username, device_id = data.get('username','').strip(), data.get('device_id','').strip()
    device_signature, device_message = data.get('device_signature',''), data.get('device_message','')
    client_ip = request.remote_addr
    if not all([username, device_id, device_signature, device_message]): return jsonify({'error': 'request failed'}), 400
    if not check_device_reg_rate(client_ip, max_attempts=5): return jsonify({'error': 'request failed'}), 429
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
        row = dict(d); row.pop('public_key', None)
        if row.get('created_at'): row['created_at'] = str(row['created_at'])
        if row.get('approved_at'): row['approved_at'] = str(row['approved_at'])
        result.append(row)
    return jsonify(result)

@app.route('/api/devices/approve', methods=['POST'])
def api_device_approve():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    device_id = request.get_json()['device_id']
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

@app.route('/api/users', methods=['GET'])
def api_get_users():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    from database import get_db, get_cursor
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT username, role FROM users ORDER BY username")
        return jsonify([dict(r) for r in cur.fetchall()])

@app.route('/api/users/add', methods=['POST'])
def api_add_user():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    username = data.get('username', '').strip()[:50]
    password = data.get('password', '')[:128]
    role     = data.get('role', 'Security Officer')[:50]
    if not username or not password: return jsonify({'error': 'username and password required'}), 400
    import bcrypt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    try:
        from database import get_db, get_cursor
        with get_db() as conn:
            cur = get_cursor(conn)
            cur.execute("INSERT INTO users (username, password_hash, role, display_name) VALUES (%s, %s, %s, %s) ON CONFLICT (username) DO NOTHING",
                        (username, hashed, role, username))
            if cur.rowcount == 0: return jsonify({'error': 'username already exists'}), 409
        log_admin('add_user', username)
        return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)}), 500

# ── MAIN ──
if __name__ == '__main__':
    print("Starting NETAD Security System — Guard AI: Level 100 Active")
    threading.Thread(target=token_cleanup_worker, daemon=True).start()
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    socketio.run(app, host=host, port=port, debug=False)
