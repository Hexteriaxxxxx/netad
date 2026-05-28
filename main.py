# main.py — NETAD Security System (Railway-compatible, optimized)
# BUILD ID: NETAD-2025-05-28-SHARED-BUFFER

from flask import Flask, request, jsonify, render_template, session, redirect, Response
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix
from block import Block
from database import (
    add_log, get_logs_today, get_logs_today_count, get_sessions, delete_session,
    get_blacklist, add_to_blacklist, forgive_ip,
    get_whitelist, add_to_whitelist, remove_from_whitelist,
    get_ai_logs, create_session, update_session_heartbeat,
    add_ai_log, get_user, cleanup_used_tokens,
    add_chat_log, get_chat_logs,
    register_device, get_device, get_all_devices,
    approve_device, reject_device, delete_device, get_pending_devices,
    is_whitelisted, is_blacklisted, get_all_failed_count,
    claim_token, get_device_public_key, clear_rate_limit,
    get_db, normalize_ip, is_valid_ip, is_valid_username, is_valid_password
)
from dotenv import load_dotenv
import os, threading, time, secrets, json, base64, re, datetime

load_dotenv()

# ── Read critical env vars once at startup and log their status ──
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '').strip()
print(f"[NETAD] GROQ_API_KEY : {'SET (' + str(len(GROQ_API_KEY)) + ' chars)' if GROQ_API_KEY else '*** MISSING — Guard AI disabled ***'}")
print(f"[NETAD] ALLOWED_ORIGIN: {os.environ.get('ALLOWED_ORIGIN', '*** MISSING ***')}")
print(f"[NETAD] DATABASE_URL  : {'SET' if os.environ.get('DATABASE_URL') else '*** MISSING ***'}")
print(f"[NETAD] SECRET_KEY    : {'SET' if os.environ.get('SECRET_KEY') else '*** MISSING ***'}")

app = Flask(__name__)
if os.environ.get('DEBUG_ENV'):
    print("=== NETAD ENV DEBUG ===")
    for k in ['SECRET_KEY','DATABASE_URL','ALLOWED_ORIGIN','GROQ_API_KEY','PORT','HOST']:
        v = os.environ.get(k,'')
        print(f"  {k}: {'SET (' + str(len(v)) + ' chars)' if v else 'MISSING'}")
    print("=== END DEBUG ===")

app.secret_key = os.environ.get('SECRET_KEY') or 'fallback_dev_key_change_in_prod'
if not os.environ.get('SECRET_KEY'):
    print("WARNING: SECRET_KEY not set — using fallback!")

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE']   = os.environ.get('SECURE_COOKIES', 'false').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', 'http://localhost:5000')
if ALLOWED_ORIGIN == '*':
    raise RuntimeError("ALLOWED_ORIGIN=* is not allowed.")
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGIN, async_mode='eventlet')

@app.after_request
def security_headers(r):
    r.headers.update({
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    })
    return r

@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    print(f"Error: {traceback.format_exc()}")
    return jsonify({'error': 'An internal error occurred.'}), 500

@socketio.on('connect')
def on_connect(): pass

@socketio.on('subscribe_dashboard')
def on_subscribe():
    if 'user' not in session: return False

# ══════════════════════════════════════════════════
# CAMERA — SHARED FRAME BUFFER
#
# Architecture:
#   webcam_stream.py → ngrok → _fetch_frames() [ONE background thread per cam]
#                                    ↓
#                            _frame_buffer[cam_id]  (latest JPEG, in memory)
#                                    ↓
#   browser 1 ──────────────────────┤
#   browser 2 ──── generate_camera_stream() reads buffer, not upstream
#   browser 7 ──────────────────────┘
#
# This means 7 users = 7 browser connections to Railway, but only
# ONE connection from Railway to ngrok. No more connection limit crashes.
# ══════════════════════════════════════════════════
CAMERA_URLS   = {1: os.environ.get('CAMERA_1_URL', ''), 2: os.environ.get('CAMERA_2_URL', '')}
_dynamic_cams: dict = {}
_consensus_granted  = False
_consensus_lock     = threading.Lock()

# Shared frame buffer — one fetch from ngrok, served to all browsers
_frame_buffer: dict  = {1: None, 2: None}
_frame_lock          = threading.Lock()
_fetcher_threads: dict = {}   # cam_id -> Thread
_fetcher_stop: dict    = {}   # cam_id -> threading.Event (signals fetcher to stop)

def set_consensus_state(g):
    global _consensus_granted
    with _consensus_lock: _consensus_granted = g

def is_consensus_granted():
    with _consensus_lock: return _consensus_granted

def get_camera_url(cam_id):
    return _dynamic_cams.get(cam_id) or CAMERA_URLS.get(cam_id, '')

def _mask_cam_url(url):
    return re.sub(r'://([^:@/]+):([^@/]+)@', r'://***:***@', url) if url else ''

def _fetch_frames(cam_id, stop_event):
    """Background thread — fetches frames from ngrok/RTSP into _frame_buffer.
    Stops cleanly on: stop_event set, cam disconnected, or 5 consecutive failures."""
    import requests as _req
    url = get_camera_url(cam_id)
    if not url:
        print(f"[CAM {cam_id}] Fetcher: no URL — exiting immediately")
        return
    is_http = url.lower().startswith('http')
    print(f"[CAM {cam_id}] Fetcher started ({'HTTP/ngrok' if is_http else 'RTSP'}): {url[:60]}...")
    consecutive_errors = 0
    MAX_ERRORS = 5  # auto-stop after 5 consecutive failures — prevents zombie threads

    while not stop_event.is_set():
        # Also stop if cam was disconnected externally (URL removed from _dynamic_cams)
        if cam_id in _dynamic_cams and _dynamic_cams.get(cam_id) != url:
            print(f"[CAM {cam_id}] Fetcher: URL changed — stopping old fetcher")
            break
        try:
            if is_http:
                with _req.get(url, stream=True, timeout=10,
                              headers={'ngrok-skip-browser-warning': 'true'}) as r:
                    if r.status_code != 200:
                        print(f"[CAM {cam_id}] Fetcher: HTTP {r.status_code} — retrying in 5s")
                        consecutive_errors += 1
                        if consecutive_errors >= MAX_ERRORS:
                            print(f"[CAM {cam_id}] Fetcher: {MAX_ERRORS} consecutive failures — auto-stopping")
                            break
                        stop_event.wait(5)
                        continue
                    print(f"[CAM {cam_id}] Fetcher: connected — content-type: {r.headers.get('Content-Type','?')}")
                    consecutive_errors = 0  # reset on successful connect
                    buf = b''
                    for chunk in r.iter_content(chunk_size=8192):
                        if stop_event.is_set(): break
                        buf += chunk
                        while True:
                            start = buf.find(b'\xff\xd8')
                            end   = buf.find(b'\xff\xd9')
                            if start != -1 and end != -1 and end > start:
                                frame = buf[start:end+2]
                                buf   = buf[end+2:]
                                if len(buf) > 2 * 1024 * 1024:
                                    buf = b''
                                with _frame_lock:
                                    _frame_buffer[cam_id] = frame
                            else:
                                break
            else:
                try:
                    import cv2
                    cap = cv2.VideoCapture(url)
                    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
                    print(f"[CAM {cam_id}] Fetcher: RTSP opened")
                    consecutive_errors = 0
                    while not stop_event.is_set():
                        ret, frame = cap.read()
                        if not ret:
                            print(f"[CAM {cam_id}] Fetcher: RTSP read failed — reconnecting")
                            cap.release()
                            consecutive_errors += 1
                            if consecutive_errors >= MAX_ERRORS:
                                print(f"[CAM {cam_id}] Fetcher: {MAX_ERRORS} consecutive failures — auto-stopping")
                                stop_event.set()
                                break
                            stop_event.wait(2)
                            cap = cv2.VideoCapture(url)
                            continue
                        consecutive_errors = 0
                        ret2, buf2 = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 65])
                        if ret2:
                            with _frame_lock:
                                _frame_buffer[cam_id] = buf2.tobytes()
                        stop_event.wait(0.125)
                    cap.release()
                except ImportError:
                    print(f"[CAM {cam_id}] Fetcher: cv2 not available — RTSP not supported on Railway")
                    break
                except Exception as e:
                    print(f"[CAM {cam_id}] Fetcher RTSP error: {e}")
        except Exception as e:
            if not stop_event.is_set():
                consecutive_errors += 1
                print(f"[CAM {cam_id}] Fetcher error ({consecutive_errors}/{MAX_ERRORS}): {e}")
                if consecutive_errors >= MAX_ERRORS:
                    print(f"[CAM {cam_id}] Fetcher: auto-stopping after {MAX_ERRORS} failures")
                    break
                stop_event.wait(5)

    # Clear buffer when fetcher stops so browsers get a clean "no signal" state
    with _frame_lock:
        _frame_buffer[cam_id] = None
    print(f"[CAM {cam_id}] Fetcher stopped cleanly")

def _ensure_fetcher(cam_id):
    """Start background frame fetcher for cam_id if not already running.
    Called by /api/camera/connect and /api/camera/stream.
    Safe to call multiple times — idempotent."""
    t = _fetcher_threads.get(cam_id)
    if t and t.is_alive():
        return  # Already running — nothing to do
    # Create a new stop event for this fetcher
    stop = threading.Event()
    _fetcher_stop[cam_id] = stop
    t = threading.Thread(target=_fetch_frames, args=(cam_id, stop), daemon=True, name=f'cam-fetcher-{cam_id}')
    _fetcher_threads[cam_id] = t
    t.start()
    print(f"[CAM {cam_id}] Started new fetcher thread")

def _stop_fetcher(cam_id):
    """Signal fetcher thread to stop. Called on disconnect."""
    stop = _fetcher_stop.get(cam_id)
    if stop:
        stop.set()
    with _frame_lock:
        _frame_buffer[cam_id] = None

def generate_camera_stream(cam_id):
    """Generator — reads latest frame from shared buffer, yields MJPEG to browser.
    Throttled to 4fps per client to keep Railway workers free for API calls."""
    no_frame_count = 0
    last_frame = None
    while True:
        with _frame_lock:
            frame = _frame_buffer.get(cam_id)
        if frame and frame is not last_frame:
            last_frame = frame
            no_frame_count = 0
            yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            time.sleep(0.25)  # 4fps — low enough to keep API responsive
        else:
            no_frame_count += 1
            if no_frame_count > 40:  # ~10s with no new frames
                if get_camera_url(cam_id):
                    _ensure_fetcher(cam_id)
                    no_frame_count = 0
                else:
                    break
            time.sleep(0.25)

@app.route('/api/camera/<int:cam_id>/stream')
def camera_stream(cam_id):
    """Shared-buffer MJPEG stream.
    Railway opens ONE upstream connection to ngrok via _fetch_frames().
    All 7 browser clients read from the same _frame_buffer — no connection limit issues."""
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    url = get_camera_url(cam_id)
    if not url:
        return jsonify({'error': 'not configured'}), 503
    if not is_consensus_granted() and cam_id not in _dynamic_cams:
        return jsonify({'error': 'consensus not met'}), 403
    # Ensure the single background fetcher is running.
    # Safe to call even if already running — idempotent.
    _ensure_fetcher(cam_id)
    alive = bool(_fetcher_threads.get(cam_id) and _fetcher_threads[cam_id].is_alive())
    print(f"[CAM {cam_id}] Browser client connected to shared stream (fetcher alive: {alive})")
    return Response(
        generate_camera_stream(cam_id),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

@app.route('/api/camera/connect', methods=['POST'])
def api_camera_connect():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    data   = request.get_json()
    cam_id = int(data.get('cam_id', 1))
    url    = data.get('url', '').strip()
    if not url: return jsonify({'error': 'missing url'}), 400
    if not re.match(r'^(rtsp|rtsps|http|https)://', url, re.IGNORECASE):
        return jsonify({'error': 'invalid URL'}), 400
    if cam_id not in [1, 2]: return jsonify({'error': 'cam_id must be 1 or 2'}), 400

    # If a fetcher is already running for this cam with a different URL,
    # stop it first so it reconnects to the new URL.
    existing_url = get_camera_url(cam_id)
    if existing_url and existing_url != url:
        print(f"[CAM {cam_id}] URL changed — stopping old fetcher before starting new one")
        _stop_fetcher(cam_id)
        time.sleep(0.5)  # brief pause to let old fetcher exit

    _dynamic_cams[cam_id] = url
    masked = _mask_cam_url(url)

    # Start the shared fetcher immediately on connect — don't wait for first browser client.
    # This means the frame buffer is warm by the time the browser requests /stream.
    _ensure_fetcher(cam_id)

    log_admin('camera_connect', f'cam{cam_id} → {masked}')
    socketio.emit('camera_connected', {'cam_id': cam_id, 'masked_url': masked})
    print(f"[CAM {cam_id}] Connected: {masked} — fetcher started")
    return jsonify({'success': True, 'cam_id': cam_id, 'masked_url': masked})

@app.route('/api/camera/disconnect', methods=['POST'])
def api_camera_disconnect():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    cam_id = int(request.get_json().get('cam_id', 1))
    _dynamic_cams.pop(cam_id, None)
    _stop_fetcher(cam_id)   # Signal fetcher to stop cleanly
    print(f"[CAM {cam_id}] Disconnected — fetcher stopped")
    socketio.emit('camera_access', {'accessible': False, 'reason': f'cam{cam_id} disconnected'})
    return jsonify({'success': True})

@app.route('/api/camera/status')
def camera_status():
    g = is_consensus_granted()
    cams = {str(i): {
        'configured': bool(get_camera_url(i)),
        'accessible': g and bool(get_camera_url(i)),
        'masked_url': _mask_cam_url(get_camera_url(i)),
        'fetcher_alive': bool(_fetcher_threads.get(i) and _fetcher_threads[i].is_alive())
    } for i in [1, 2]}
    return jsonify({'accessible': g, 'cameras': cams})

# ══════════════════════════════════════════════════
# INLINE NODES
# ══════════════════════════════════════════════════

def node1_password(payload):
    import bcrypt, hashlib
    u, p = payload.get('username', ''), payload.get('password', '')
    if not u or not p: return 'FAIL'
    try:
        user = get_user(u)
        if not user: return 'FAIL'
        s  = user['password_hash']
        ok = bcrypt.checkpw(p.encode(), s.encode()) if s.startswith('$2') else s == hashlib.sha256(p.encode()).hexdigest()
        print(f"Node 1 {'PASS' if ok else 'FAIL'}: {u}")
        return 'PASS' if ok else 'FAIL'
    except Exception as e: print(f"Node 1 err: {e}"); return 'FAIL'

def node2_timestamp(payload):
    ts  = payload.get('login_timestamp', 0) or payload.get('timestamp', 0)
    age = time.time() - ts
    ok  = 0 <= age <= 30
    print(f"Node 2 {'PASS' if ok else 'FAIL'}: {age:.1f}s")
    return 'PASS' if ok else 'FAIL'

def node3_ip_whitelist(payload):
    if os.environ.get('DISABLE_IP_WHITELIST', '').lower() == 'true':
        print("Node 3 PASS: whitelist disabled via DISABLE_IP_WHITELIST")
        return 'PASS'
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
        raw     = base64.b64decode(sig_b64)
        r, s    = raw[:32], raw[32:]
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
    return 'PASS' if (token and claim_token(token)) else 'FAIL'

def node6_rate_limit(payload):
    ip, MAX = payload.get('ip', 'unknown'), 5
    if is_blacklisted(ip): print(f"Node 6 FAIL: {ip} blacklisted"); return 'FAIL'
    if is_whitelisted(ip): print(f"Node 6 PASS: {ip} whitelisted"); return 'PASS'
    count = get_all_failed_count(ip)
    print(f"Node 6 checking: {ip} has {count}/{MAX} failed attempts")
    if count >= MAX:
        add_to_blacklist(ip, 'temporary', 1800)
        print(f"Node 6 FAIL: {ip} auto-blacklisted ({count} attempts)")
        return 'FAIL'
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
        try: votes[i] = fn(payload)
        except Exception as e: print(f"Node {i+1} err: {e}"); votes[i] = 'FAIL'
    threads = [threading.Thread(target=run_node, args=(i, n, f), daemon=True) for i, (n, f) in enumerate(INLINE_NODES)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=6)
    votes = [v or 'FAIL' for v in votes]
    steps   = [{'layer': INLINE_NODES[i][0], 'result': votes[i]} for i in range(len(INLINE_NODES))]
    granted = all(v == 'PASS' for v in votes)
    print(f"Consensus: {votes} → {'GRANTED' if granted else 'DENIED'}")
    return ('GRANTED' if granted else 'DENIED'), votes, steps

# ── CSRF ──
_csrf_tokens: dict = {}
_csrf_lock = threading.Lock()

def generate_csrf():
    token = secrets.token_hex(32)
    now   = time.time()
    with _csrf_lock:
        _csrf_tokens[token] = now + 300
        expired = [k for k, v in _csrf_tokens.items() if v < now]
        for k in expired: del _csrf_tokens[k]
    return token

def validate_csrf(token):
    with _csrf_lock:
        if token not in _csrf_tokens: return False
        if _csrf_tokens[token] < time.time():
            del _csrf_tokens[token]; return False
        del _csrf_tokens[token]; return True

# ── RATE LIMITERS ──
_public_rate: dict = {}
_public_rate_lock  = threading.Lock()

def public_rate_ok(ip, max_per_min=15):
    now = time.time()
    with _public_rate_lock:
        bucket = _public_rate.setdefault(ip, [])
        _public_rate[ip] = [t for t in bucket if now - t < 60]
        if len(_public_rate[ip]) >= max_per_min: return False
        _public_rate[ip].append(now); return True

_dev_reg: dict = {}
_dev_reg_lock  = threading.Lock()

def check_dev_rate(ip, max_attempts=20, window=3600):
    now = time.time()
    with _dev_reg_lock:
        _dev_reg.setdefault(ip, [])
        _dev_reg[ip] = [t for t in _dev_reg[ip] if now - t < window]
        if len(_dev_reg[ip]) >= max_attempts: return False
        _dev_reg[ip].append(now); return True

# ── CLEANUP WORKER ──
_retrain_tick = 0

def _retrain_from_logs():
    try:
        from ai.anomaly import retrain as _retrain
        from datetime import timezone, timedelta
        with get_db() as conn:
            from database import get_cursor as _gc
            cur = _gc(conn)
            cur.execute("""
                SELECT ip, username, timestamp FROM logs
                WHERE timestamp > NOW() - INTERVAL '30 days'
                  AND result IN ('GRANTED', 'DENIED', 'SUSPICIOUS')
                ORDER BY timestamp DESC LIMIT 2000
            """)
            rows = cur.fetchall()
        if len(rows) < 50:
            print(f"[retrain] Only {len(rows)} samples — need ≥50, skipping"); return
        samples = []
        for r in rows:
            dt = r['timestamp']
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ph_dt = dt.astimezone(timezone(timedelta(hours=8)))
            try: last_octet = int(str(r['ip']).split('.')[-1])
            except: last_octet = 0
            samples.append([ph_dt.hour, 1, 1, 1 if ph_dt.weekday() >= 5 else 0, len(r['username'] or ''), last_octet])
        _retrain(samples)
        print(f"[retrain] Done — {len(samples)} real samples")
    except Exception as e:
        print(f"[retrain] Error: {e}")

def token_cleanup_worker():
    global _retrain_tick
    while True:
        try: cleanup_used_tokens()
        except Exception as e: print(f"Token cleanup: {e}")
        now = time.time()
        with _votes_lock:
            expired = [vid for vid, v in _pending_votes.items()
                      if not v['executed'] and not v['cancelled'] and now > v['expires_at']]
            for vid in expired:
                v = _pending_votes[vid]
                v['cancelled'] = True
                socketio.emit('vote_resolved', {
                    'vote_id': vid, 'result': 'expired',
                    'description': _vote_description(v['action'], v['args']),
                    'requester': v['requester']
                })
        with _public_rate_lock:
            stale = [ip for ip, ts in _public_rate.items() if not ts or now - max(ts) > 120]
            for ip in stale: del _public_rate[ip]
        with _dev_reg_lock:
            stale = [ip for ip, ts in _dev_reg.items() if not ts or now - max(ts) > 3600]
            for ip in stale: del _dev_reg[ip]
        _retrain_tick += 1
        if _retrain_tick >= 720:
            _retrain_tick = 0
            print("[retrain] 24-hour trigger — retraining anomaly model...")
            threading.Thread(target=_retrain_from_logs, daemon=True).start()
        time.sleep(120)

def mask_ip(ip):
    parts = ip.split('.')
    return f"x.x.x.{parts[-1]}" if len(parts) == 4 else 'x.x.x.x'

def log_admin(action, target):
    try:
        admin = session.get('user', 'system')
        ip    = request.remote_addr if request else 'internal'
        add_log(admin, ip, 'ADMIN', f'{action}: {target}')
    except Exception: pass

def _notify_guard(message):
    try:
        add_chat_log('system', message)
        socketio.emit('chat_message', {'role': 'system', 'message': message})
    except Exception: pass

# ══════════════════════════════════════════════════
# THREAT DETECTION ENGINE
# ══════════════════════════════════════════════════
_SQL_PATTERNS = [
    "' or ", "' or'", "1=1", "or 1=1", "' --", "'; --", "drop table",
    "union select", "insert into", "delete from", "'; drop", "xp_",
    "exec(", "execute(", "cast(", "convert(", "char(", "0x",
    "benchmark(", "sleep(", "waitfor", "information_schema",
]
_ATTACK_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "hydra", "medusa",
    "burpsuite", "burp suite", "metasploit", "nessus", "openvas",
    "python-requests", "go-http-client", "curl/", "wget/",
    "zgrab", "shodan", "censys",
]

_valid_users_cache: dict = {'users': set(), 'ts': 0}
_valid_users_lock = threading.Lock()

def _get_valid_users():
    now = time.time()
    with _valid_users_lock:
        if now - _valid_users_cache['ts'] < 60 and _valid_users_cache['users']:
            return _valid_users_cache['users']
    try:
        from database import get_cursor as _gc
        with get_db() as conn:
            cur = _gc(conn)
            cur.execute("SELECT username FROM users")
            users = {row['username'] for row in cur.fetchall()}
        with _valid_users_lock:
            _valid_users_cache['users'] = users
            _valid_users_cache['ts'] = now
        return users
    except Exception:
        return _valid_users_cache['users'] or set()

def detect_threats(username, ip, data, result, votes, user_agent='', csrf_failed=False):
    threats = []
    ua      = (user_agent or '').lower()
    granted = result == 'GRANTED'

    for field, val in [('username', data.get('_raw_username', username)), ('password', data.get('_raw_password', ''))]:
        v = val.lower()
        for p in _SQL_PATTERNS:
            if p in v:
                threats.append({'type': 'SQL_INJECTION', 'description': f'SQL injection in {field}: "{p}"', 'severity': 'CRITICAL', 'score': -0.9})
                break

    for agent in _ATTACK_AGENTS:
        if agent in ua:
            threats.append({'type': 'ATTACK_TOOL', 'description': f'Attack tool UA: {user_agent[:80]}', 'severity': 'HIGH', 'score': -0.8})
            break

    if not granted:
        if username and username not in _get_valid_users():
            threats.append({'type': 'UNKNOWN_USERNAME', 'description': f'Unknown username: "{username}"', 'severity': 'MEDIUM', 'score': -0.5})

        if votes and votes[0] == 'FAIL':
            try:
                count = get_all_failed_count(ip)
                if count >= 3:
                    threats.append({'type': 'BRUTE_FORCE', 'description': f'Rate limit hit — {count} failed attempts from {mask_ip(ip)}', 'severity': 'HIGH', 'score': -0.85})
            except Exception: pass
        elif votes and votes[0] == 'PASS':
            try:
                count = get_all_failed_count(ip)
                if count >= 3:
                    threats.append({'type': 'BRUTE_FORCE', 'description': f'Multiple failed attempts — {count} from {mask_ip(ip)} (currently under limit)', 'severity': 'HIGH', 'score': -0.75})
            except Exception: pass

        if csrf_failed:
            threats.append({'type': 'CSRF_BYPASS_ATTEMPT', 'description': f'Invalid/missing CSRF token from {mask_ip(ip)}', 'severity': 'HIGH', 'score': -0.75})

        if len(votes) >= 6 and votes[5] == 'FAIL':
            threats.append({'type': 'REPLAY_ATTACK', 'description': f'Token already consumed — replay attack from {mask_ip(ip)}', 'severity': 'HIGH', 'score': -0.8})

        ph_hour = (datetime.datetime.now(datetime.timezone.utc).hour + 8) % 24
        if ph_hour >= 22 or ph_hour < 5:
            threats.append({'type': 'OFF_HOURS', 'description': f'Failed login at {ph_hour:02d}:00 PH — outside normal hours (5AM-10PM)', 'severity': 'MEDIUM', 'score': -0.3})

    if len(votes) >= 2 and votes[1] == 'PASS' and not granted:
        if username in _get_valid_users():
            threats.append({'type': 'CREDENTIAL_LEAK', 'description': f'Correct password but denied — password may be compromised for "{username}"', 'severity': 'CRITICAL', 'score': -0.95})

    return threats

_groq_semaphore = threading.Semaphore(5)

def _groq_analyze_async(threat):
    def _run():
        if not _groq_semaphore.acquire(blocking=False):
            print(f"[Groq] semaphore full — dropped analysis for {threat.get('type','?')} from {threat.get('ip','?')}")
            return
        try:
            key = GROQ_API_KEY
            if not key: return
            from groq import Groq
            client = Groq(api_key=key)
            r = client.chat.completions.create(
                model='llama-3.3-70b-versatile',
                messages=[{'role': 'user', 'content': (
                    f"NETAD security event — 2 sentences max.\n"
                    f"Type: {threat['type']} | Severity: {threat['severity']}\n"
                    f"Details: {threat['description']}\n"
                    f"What is it, why dangerous, what should admin do?"
                )}],
                max_tokens=100, temperature=0.2
            )
            analysis = r.choices[0].message.content.strip()
            _notify_guard(f"🔍 [{threat['severity']}] {threat['type']}\n{threat['description']}\n{analysis}")
            socketio.emit('ai_alert', {
                'ip': mask_ip(str(threat.get('ip', ''))),
                'username': threat.get('username', ''),
                'score': threat.get('score', -0.5),
                'message': f"[{threat['severity']}] {threat['type']}: {threat['description']}",
                'groq_analysis': analysis
            })
        except Exception as e: print(f"Groq analysis err: {e}")
        finally: _groq_semaphore.release()
    threading.Thread(target=_run, daemon=True).start()

def log_all_threats(username, ip, data, result, votes, user_agent='', csrf_failed=False):
    threats = detect_threats(username, ip, data, result, votes, user_agent, csrf_failed)
    for t in threats:
        add_ai_log(ip=ip, username=username, description=t['description'], score=t['score'], flagged=True)
        socketio.emit('new_ai_log', {
            'ip': mask_ip(ip), 'username': username,
            'description': t['description'], 'score': t['score'],
            'severity': t['severity'], 'type': t['type'],
            'flagged': True, 'timestamp': str(datetime.datetime.now())
        })
        t['ip'] = ip; t['username'] = username
        if t.get('severity') in ('HIGH', 'CRITICAL'):
            _groq_analyze_async(t)

# ══════════════════════════════════════════════════
# GUARD AI
# ══════════════════════════════════════════════════
_ctx_cache: dict = {'data': None, 'ts': 0}
_ctx_lock = threading.Lock()
CTX_TTL = 30

def _get_system_context():
    now = time.time()
    with _ctx_lock:
        if _ctx_cache['data'] and now - _ctx_cache['ts'] < CTX_TTL:
            return _ctx_cache['data']
    try:
        with get_db() as conn:
            from database import get_cursor as _gc
            cur = _gc(conn)
            cur.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10")
            logs = cur.fetchall()
            cur.execute("SELECT * FROM ai_logs ORDER BY timestamp DESC LIMIT 5")
            ai_logs = cur.fetchall()
            cur.execute("""SELECT *, CASE WHEN last_seen > NOW()-INTERVAL '60 seconds'
                THEN true ELSE false END AS online FROM sessions ORDER BY last_seen DESC""")
            sessions = cur.fetchall()
            cur.execute("SELECT COUNT(*) as c FROM blacklist")
            bl_count = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM whitelist")
            wl_count = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM device_keys WHERE status='pending'")
            pending = cur.fetchone()['c']

        online = [s for s in sessions if s.get('online')]
        ctx  = "=== LIVE NETAD STATE ===\n"
        ctx += f"Camera: {'OPEN' if is_consensus_granted() else 'LOCKED'} | Nodes: ALL 6 ONLINE | Pending devices: {pending}\n"
        ctx += f"Sessions ({len(online)} online):\n"
        for s in sessions:
            ctx += f"  {s.get('username','')} | {'ON' if s.get('online') else 'OFF'} | {mask_ip(str(s.get('ip','')))} | {s.get('role','')}\n"
        ctx += "Recent logs:\n"
        for l in logs:
            ctx += f"  [{str(l.get('timestamp',''))[:19]}] {l.get('result','')} user={l.get('username','')} ip={mask_ip(str(l.get('ip','')))} {l.get('reason','')}\n"
        ctx += "AI flags:\n"
        for a in ai_logs:
            ctx += f"  {mask_ip(str(a.get('ip','')))} user={a.get('username','')} score={a.get('score','')} flagged={a.get('flagged','')}\n"
        ctx += f"Blacklisted: {bl_count} | Whitelisted: {wl_count}\n"

        with _ctx_lock:
            _ctx_cache['data'] = ctx
            _ctx_cache['ts']   = now
        return ctx
    except Exception as e:
        return _ctx_cache['data'] or f"(context error: {e})"

GUARD_TOOLS = [
    {'type': 'function', 'function': {'name': 'block_ip', 'description': 'Block a specific IP address for 30 minutes. REQUIRES: explicit IP in x.x.x.x format from user message. Do NOT infer IP from context.', 'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string', 'description': 'Must be explicit IPv4 address from user message'}}, 'required': ['ip']}}},
    {'type': 'function', 'function': {'name': 'forgive_ip', 'description': 'Remove a specific IP from blacklist. REQUIRES: explicit IP in x.x.x.x format and explicit forgive/unblock command from user.', 'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}}},
    {'type': 'function', 'function': {'name': 'clear_rate_limit', 'description': 'Clear rate limit for a specific IP. REQUIRES: explicit IP in x.x.x.x format AND explicit clear/reset command. Asking IF it was cleared is NOT a command.', 'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}}},
    {'type': 'function', 'function': {'name': 'add_whitelist', 'description': 'Add a specific IP to whitelist. REQUIRES: explicit IP and explicit add/whitelist command.', 'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}, 'label': {'type': 'string'}}, 'required': ['ip']}}},
    {'type': 'function', 'function': {'name': 'remove_whitelist', 'description': 'Remove a specific IP from whitelist. REQUIRES: explicit IP and explicit remove command.', 'parameters': {'type': 'object', 'properties': {'ip': {'type': 'string'}}, 'required': ['ip']}}},
    {'type': 'function', 'function': {'name': 'kick_session', 'description': 'Force logout a specific user. ONLY callable by admin (Gian). REQUIRES: explicit username and explicit kick command. NEVER call if sender is not admin.', 'parameters': {'type': 'object', 'properties': {'username': {'type': 'string'}}, 'required': ['username']}}},
    {'type': 'function', 'function': {'name': 'connect_camera', 'description': 'Connect a camera stream URL. REQUIRES: full URL starting with https:// or rtsp://', 'parameters': {'type': 'object', 'properties': {'cam_id': {'type': 'integer'}, 'url': {'type': 'string'}}, 'required': ['cam_id', 'url']}}},
]

# ══════════════════════════════════════════════════
# MAJORITY VOTE SYSTEM
# ══════════════════════════════════════════════════
_pending_votes: dict = {}
_votes_lock = threading.Lock()
VOTE_TIMEOUT  = 300
VOTES_REQUIRED = 2
VOTEABLE_ACTIONS = {'block_ip','forgive_ip','clear_rate_limit','add_whitelist','remove_whitelist','kick_session'}

def _vote_description(action, args):
    if action == 'block_ip':         return f"Block {args.get('ip')} for 30 minutes"
    if action == 'forgive_ip':        return f"Unblock {args.get('ip')} from blacklist"
    if action == 'clear_rate_limit':  return f"Clear rate limit for {args.get('ip')}"
    if action == 'add_whitelist':     return f"Add {args.get('ip')} to whitelist ({args.get('label','')})"
    if action == 'remove_whitelist':  return f"Remove {args.get('ip')} from whitelist"
    if action == 'kick_session':      return f"Kick {args.get('username')} from system"
    return action

def _create_vote(action, args, requester):
    vote_id = secrets.token_hex(8)
    now = time.time()
    vote = {
        'id': vote_id, 'action': action, 'args': args,
        'requester': requester,
        'approvals': {requester},
        'rejections': set(),
        'created_at': now, 'expires_at': now + VOTE_TIMEOUT,
        'executed': False, 'cancelled': False
    }
    with _votes_lock:
        _pending_votes[vote_id] = vote
    desc = _vote_description(action, args)
    socketio.emit('vote_pending', {
        'vote_id': vote_id, 'action': action, 'args': args,
        'description': desc, 'requester': requester,
        'approvals': list(vote['approvals']),
        'approvals_count': 1, 'required': VOTES_REQUIRED,
        'expires_at': now + VOTE_TIMEOUT
    })
    return vote_id, desc

def _execute_action(action, args, sender='system'):
    try:
        if action == 'block_ip':
            ip = args['ip']; add_to_blacklist(ip, 'temporary', 1800)
            log_admin(f'guard:block_ip', f'{ip} (by {sender})')
            socketio.emit('guard_action', {'action': 'block_ip', 'ip': ip})
            return f"Blocked {ip} for 30 min."
        elif action == 'forgive_ip':
            ip = args['ip']; forgive_ip(ip); clear_rate_limit(ip)
            log_admin(f'guard:forgive_ip', f'{ip} (by {sender})')
            socketio.emit('guard_action', {'action': 'forgive_ip', 'ip': ip})
            return f"Forgiven {ip}."
        elif action == 'clear_rate_limit':
            ip = args['ip']; clear_rate_limit(ip)
            log_admin(f'guard:clear_rate_limit', f'{ip} (by {sender})')
            socketio.emit('guard_action', {'action': 'clear_rate_limit', 'ip': ip})
            return f"Rate limit cleared for {ip}."
        elif action == 'add_whitelist':
            ip = args['ip']; add_to_whitelist(ip, args.get('label', f'Guard approved by {sender}'))
            log_admin(f'guard:add_whitelist', f'{ip} (by {sender})')
            socketio.emit('guard_action', {'action': 'add_whitelist', 'ip': ip})
            return f"Added {ip} to whitelist."
        elif action == 'remove_whitelist':
            ip = args['ip']; remove_from_whitelist(ip)
            log_admin(f'guard:remove_whitelist', f'{ip} (by {sender})')
            socketio.emit('guard_action', {'action': 'remove_whitelist', 'ip': ip})
            return f"Removed {ip} from whitelist."
        elif action == 'kick_session':
            u = args['username']; delete_session(u)
            log_admin(f'guard:kick_session', f'{u} (by {sender})')
            socketio.emit('session_kicked', {'username': u})
            return f"Kicked {u}."
        elif action == 'connect_camera':
            cam_id = int(args['cam_id']); url = args['url']
            if not re.match(r'^(rtsp|rtsps|http|https)://', url, re.IGNORECASE): return "Invalid URL."
            existing = get_camera_url(cam_id)
            if existing and existing != url:
                _stop_fetcher(cam_id)
                time.sleep(0.5)
            _dynamic_cams[cam_id] = url
            _ensure_fetcher(cam_id)
            masked = _mask_cam_url(url)
            log_admin('guard:camera_connect', f'cam{cam_id} → {masked} (by {sender})')
            socketio.emit('camera_connected', {'cam_id': cam_id, 'masked_url': masked})
            return f"Camera {cam_id} connected: {masked}"
        return f"Unknown action: {action}"
    except Exception as e: return f"Action error: {e}"

def _run_tool(tool_name, args, sender='unknown'):
    if tool_name in VOTEABLE_ACTIONS:
        vote_id, desc = _create_vote(tool_name, args, sender)
        return (f"⏳ VOTE CREATED — {desc}\n"
                f"Vote ID: {vote_id[:8]}\n"
                f"Approvals: 1/{VOTES_REQUIRED} ({sender} requested)\n"
                f"Waiting for {VOTES_REQUIRED-1} more teammate approval.\n"
                f"Teammates will see Approve/Reject buttons in this chat.\n"
                f"Expires in 5 minutes.")
    return _execute_action(tool_name, args, sender)

GUARD_SYSTEM_PROMPT = """You are NETAD Guard — AI security officer for the NETAD multi-layer camera security system. Built by a 7-person team in the Philippines.

ARCHITECTURE — 6 nodes ALL must PASS (run in parallel):
Node 1: Password (bcrypt cost-12) | Node 2: Timestamp (30s expiry, anti-replay)
Node 3: IP whitelist | Node 4: ECDSA P-256 device signature (private key never leaves browser)
Node 5: One-time session token (atomic claim) | Node 6: Rate limit (5 failures/hr → 30min block)
AI Pre-filter: Isolation Forest (PH timezone-aware) — runs BEFORE nodes, can block before consensus

DEVICE REGISTRATION POLICY:
- ALL device registrations go to PENDING — no auto-approve, including admin
- Admin must approve each device via Dashboard → Devices tab
- Only ONE approved device per user at a time — approving a new device revokes the old one
- All 7 users have equal privileges — no special admin bypass

TEAM: admin(Gian), kevin, josiah, jm, karl, nico, lj
NORMAL PATTERNS: PH IPs, 5AM-10PM PH time, 1 device each, 1-3 logins/day
SUSPICIOUS: midnight-4AM PH | 3+ attempts/60s | unknown usernames | non-PH IPs

═══════════════════════════════════════════
CRITICAL RULES — READ CAREFULLY
═══════════════════════════════════════════

RULE 1 — TOOL USE IS DESTRUCTIVE. ONLY call a tool when:
  • The user uses an EXPLICIT ACTION VERB targeting a SPECIFIC object
  • Examples that SHOULD trigger tools:
    - "Block 192.168.1.9" → block_ip
    - "Approve kevin's device" → NOT a tool (use dashboard)
    - "Forgive 103.196.139.63" → forgive_ip
    - "Kick jm" → kick_session
    - "Clear rate limit for 103.196.139.63" → clear_rate_limit
    - "Connect camera https://xxx.ngrok-free.app/video" → connect_camera
  • Examples that should NEVER trigger tools (just answer):
    - "Did the attempts reset?" → explain the reset schedule
    - "Who's online?" → list from context
    - "What happened earlier?" → describe from logs
    - "Is the rate limit cleared?" → check context, report status
    - Any question ending in "?" → almost always informational
    - Anything with "did", "has", "is", "was", "can", "what", "who", "when", "why", "how" → informational

RULE 2 — NEVER assume a question is a command.
RULE 3 — When unsure if action is intended, ASK FIRST.
RULE 4 — Mask all IPs as x.x.x.X in responses.
RULE 5 — Be concise (3-4 short paragraphs max). Report threats proactively.
RULE 6 — "Attempts today" ≠ rate limit. Rate limit is per-IP per-hour.

CAMERA: When user explicitly asks to connect a camera with a URL, call connect_camera immediately.

DEMO ANSWER — "Can Sir log in with the password?":
"No. Password passes Node 1 only. Node 3 rejects his IP (not whitelisted). Node 4 rejects his device — his browser has no approved ECDSA key in the DB, and private keys cannot be exported from WebCrypto. Two independent cryptographic layers block him. Camera stays locked."
"""

@app.route('/api/chat', methods=['POST'])
def api_chat():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    if not public_rate_ok(request.remote_addr, max_per_min=5):
        return jsonify({'error': 'rate limited'}), 429
    d   = request.get_json()
    msg = d.get('message', '').strip()
    if not msg: return jsonify({'error': 'empty'})
    key = GROQ_API_KEY
    if not key: return jsonify({'reply': 'Guard AI unavailable — GROQ_API_KEY not configured on Railway.'})

    sender = session.get('user', 'unknown')
    add_chat_log('user', msg, sender=sender)
    socketio.emit('chat_message', {'role': 'user', 'message': msg, 'sender': sender})

    history  = get_chat_logs(16)
    sender_context = f"\n=== CURRENT USER ===\nSender: {sender} | Role: {'admin' if sender == 'admin' else 'member'}\nOnly admin (Gian) can use kick_session tool.\n"
    messages = [{'role': 'system', 'content': GUARD_SYSTEM_PROMPT + sender_context + "\n" + _get_system_context()}]
    for m in history:
        if m.get('role') == 'system': continue
        messages.append({'role': m.get('role', 'user'), 'content': m.get('message', '')})
    messages.append({'role': 'user', 'content': msg})

    try:
        from groq import Groq
        client  = Groq(api_key=key)
        actions = []
        resp    = client.chat.completions.create(
            model='llama-3.3-70b-versatile', messages=messages,
            tools=GUARD_TOOLS, tool_choice='auto', max_tokens=1024, temperature=0.3
        )
        mo = resp.choices[0].message
        if mo.tool_calls:
            messages.append({'role': 'assistant', 'content': mo.content or '',
                'tool_calls': [{'id': tc.id, 'type': 'function', 'function': {'name': tc.function.name, 'arguments': tc.function.arguments}} for tc in mo.tool_calls]})
            for tc in mo.tool_calls:
                args   = json.loads(tc.function.arguments)
                result = _run_tool(tc.function.name, args, sender=sender)
                actions.append({'tool': tc.function.name, 'args': args, 'result': result})
                messages.append({'role': 'tool', 'tool_call_id': tc.id, 'content': result})
                with _ctx_lock: _ctx_cache['ts'] = 0
            fu    = client.chat.completions.create(model='llama-3.3-70b-versatile', messages=messages, max_tokens=512, temperature=0.3)
            reply = fu.choices[0].message.content.strip()
        else:
            reply = (mo.content or '').strip() or 'No response.'

        add_chat_log('assistant', reply)
        socketio.emit('chat_message', {'role': 'assistant', 'message': reply})
        return jsonify({'reply': reply, 'action_result': actions})
    except Exception as e:
        return jsonify({'reply': f'Guard unavailable: {e}'})

@app.route('/api/vote/approve', methods=['POST'])
def api_vote_approve():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    voter    = session.get('user')
    vote_id  = (request.get_json() or {}).get('vote_id', '')
    should_execute = False
    vote_snap = None
    with _votes_lock:
        vote = _pending_votes.get(vote_id)
        if not vote:                       return jsonify({'error': 'Vote not found'}), 404
        if vote['executed']:               return jsonify({'error': 'Already executed'}), 400
        if vote['cancelled']:              return jsonify({'error': 'Already cancelled'}), 400
        if time.time() > vote['expires_at']: return jsonify({'error': 'Vote expired'}), 400
        if voter == vote['requester']:     return jsonify({'error': 'Cannot approve your own request'}), 400
        if voter in vote['rejections']:    return jsonify({'error': 'Already rejected'}), 400
        vote['approvals'].add(voter)
        if len(vote['approvals']) >= VOTES_REQUIRED:
            vote['executed'] = True
            should_execute = True
        vote_snap = {'action': vote['action'], 'args': vote['args'],
                     'requester': vote['requester'], 'approvals': list(vote['approvals'])}
    if should_execute:
        result = _execute_action(vote_snap['action'], vote_snap['args'], vote_snap['requester'])
        socketio.emit('vote_resolved', {
            'vote_id': vote_id, 'result': 'approved',
            'description': _vote_description(vote_snap['action'], vote_snap['args']),
            'approved_by': voter, 'requester': vote_snap['requester'],
            'tool_result': result
        })
        log_admin(f'vote:approved', f"{vote_snap['action']} — approved by {voter}, requested by {vote_snap['requester']}")
        return jsonify({'success': True, 'executed': True, 'result': result})
    else:
        socketio.emit('vote_update', {
            'vote_id': vote_id,
            'approvals': vote_snap['approvals'],
            'approvals_count': len(vote_snap['approvals']),
            'required': VOTES_REQUIRED
        })
        return jsonify({'success': True, 'executed': False})

@app.route('/api/vote/reject', methods=['POST'])
def api_vote_reject():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    voter   = session.get('user')
    vote_id = (request.get_json() or {}).get('vote_id', '')
    with _votes_lock:
        vote = _pending_votes.get(vote_id)
        if not vote:             return jsonify({'error': 'Vote not found'}), 404
        if vote['executed']:     return jsonify({'error': 'Already executed'}), 400
        if vote['cancelled']:    return jsonify({'error': 'Already cancelled'}), 400
        vote['cancelled'] = True
        vote['rejections'].add(voter)
        desc = _vote_description(vote['action'], vote['args'])
        requester = vote['requester']
    socketio.emit('vote_resolved', {
        'vote_id': vote_id, 'result': 'rejected',
        'description': desc, 'rejected_by': voter, 'requester': requester
    })
    log_admin('vote:rejected', f"{desc} — rejected by {voter}")
    return jsonify({'success': True})

@app.route('/api/vote/pending')
def api_vote_pending():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    now = time.time()
    result = []
    with _votes_lock:
        for v in _pending_votes.values():
            if not v['executed'] and not v['cancelled'] and now < v['expires_at']:
                result.append({
                    'vote_id': v['id'], 'action': v['action'], 'args': v['args'],
                    'description': _vote_description(v['action'], v['args']),
                    'requester': v['requester'],
                    'approvals': list(v['approvals']),
                    'approvals_count': len(v['approvals']),
                    'required': VOTES_REQUIRED,
                    'expires_at': v['expires_at']
                })
    return jsonify(result)

@app.route('/api/action/request', methods=['POST'])
def api_action_request():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    d = request.get_json()
    action = d.get('action', '')
    args   = d.get('args', {})
    sender = session.get('user', 'unknown')
    if action not in VOTEABLE_ACTIONS:
        return jsonify({'error': f'action {action} not voteable'}), 400
    if action in ('block_ip','forgive_ip','clear_rate_limit','add_whitelist','remove_whitelist'):
        if not args.get('ip'): return jsonify({'error': 'missing ip'}), 400
    if action == 'kick_session':
        if not args.get('username'): return jsonify({'error': 'missing username'}), 400
    vote_id, desc = _create_vote(action, args, sender)
    log_admin(f'vote:requested', f'{desc} (by {sender} via dashboard)')
    return jsonify({'success': True, 'vote_id': vote_id, 'description': desc})

@app.route('/api/chat/history')
def api_chat_history():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    return jsonify([{**dict(l), 'timestamp': str(l['timestamp'])} for l in get_chat_logs(50)])

# ── ROUTES ──
@app.route('/')
def index(): return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect('/logout')
    return render_template('dashboard.html', user=session.get('user', 'admin'))

@app.route('/logout')
def logout():
    user = session.get('user')
    if user:
        delete_session(user)
        socketio.emit('user_logout', {'username': user})
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
    client_ip     = normalize_ip(request.remote_addr or '')
    user_agent    = request.headers.get('User-Agent', '')
    data['_raw_username'] = data.get('username', '')
    data['_raw_password'] = data.get('password', '')
    csrf_ok = validate_csrf(csrf_token)
    if not csrf_ok:
        add_log(username, client_ip, 'DENIED', 'Invalid CSRF token')
        threading.Thread(target=log_all_threats, args=(username, client_ip, data, 'DENIED', [], user_agent, True), daemon=True).start()
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
        'login_timestamp': data.get('login_timestamp', 0),
        'device_id': data.get('device_id', ''),
        'device_signature': data.get('device_signature', ''),
        'device_message': data.get('device_message', ''),
    }
    result, votes, steps = run_consensus(payload)
    granted = result == 'GRANTED'
    if granted and is_blacklisted(client_ip):
        granted = False
        result = 'DENIED'
        print(f"[login] Overriding GRANTED — {client_ip} is blacklisted")
        steps = [{'layer': s['layer'], 'result': 'FAIL' if s['layer'] == 'Rate Limiting' else s['result']} for s in steps]
    add_log(username, client_ip, result)
    threading.Thread(target=log_all_threats, args=(username, client_ip, data, result, votes, user_agent, False), daemon=True).start()
    if granted:
        user_data = get_user(username)
        role = user_data['role'] if user_data else 'Member'
        sess_token = secrets.token_hex(32)
        socketio.emit('session_kicked', {'username': username, 'reason': 'new_login'})
        create_session(username, client_ip, role, sess_token)
        session['user'] = username
        session['token'] = sess_token
        set_consensus_state(True)
        wl_label = f'{username} (auto: login {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")})'
        add_to_whitelist(client_ip, wl_label)
        socketio.emit('ip_whitelisted', {'ip': client_ip, 'label': wl_label, 'by': 'system'})
        print(f"[login] Auto-whitelisted {client_ip} for {username}")
        socketio.emit('camera_access', {'accessible': True, 'reason': '6/6 consensus granted'})
    socketio.emit('login_attempt', {'username': username, 'ip': client_ip, 'result': result, 'votes': votes})
    return jsonify({'granted': granted, 'user': username, 'error': '' if granted else 'authentication failed', 'steps': steps, 'votes': votes})

@app.route('/api/my-ip')
def api_my_ip():
    raw = request.remote_addr
    normalized = normalize_ip(raw or '')
    whitelisted = is_whitelisted(normalized)
    return jsonify({
        'raw_ip': raw,
        'normalized_ip': normalized,
        'whitelisted': whitelisted,
        'x_forwarded_for': request.headers.get('X-Forwarded-For', 'not set'),
        'x_real_ip': request.headers.get('X-Real-IP', 'not set')
    })

@app.route('/api/stats')
def api_stats():
    try:
        with get_db() as conn:
            from database import get_cursor as _gc
            cur = _gc(conn)
            cur.execute("SELECT COUNT(*) as c FROM blacklist")
            blocked = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM (SELECT flagged FROM ai_logs ORDER BY timestamp DESC LIMIT 20) sub WHERE flagged = true")
            threats = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM device_keys WHERE status = 'pending'")
            pending = cur.fetchone()['c']
        db_ok = True
    except Exception:
        blocked, threats, pending, db_ok = 0, 0, 0, False
    layers_active = 6 if db_ok else 0
    return jsonify({'layers': f'{layers_active}/6', 'threats': threats, 'blocked': blocked, 'pending': pending})

@app.route('/api/node-status')
def node_status():
    try:
        with get_db() as conn: conn.cursor().execute('SELECT 1')
        db_ok = True
    except Exception: db_ok = False
    return jsonify({'password': db_ok, 'timestamp': True, 'ip_whitelist': db_ok, 'digital_sig': True, 'session_token': db_ok, 'rate_limit': db_ok})

@app.route('/api/logs')
def api_logs():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    return jsonify([{**dict(l), 'timestamp': str(l['timestamp'])} for l in get_logs_today(50)])

@app.route('/api/metrics')
def api_metrics():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    try:
        attempts   = get_logs_today_count()
        blacklist  = get_blacklist()
        ai_logs    = get_ai_logs(20)
        sessions   = get_sessions()
        devices    = get_all_devices()
        return jsonify({
            'attempts':  attempts,
            'blocked':   len(blacklist),
            'ai_alerts': len([a for a in ai_logs if a.get('flagged')]),
            'online':    len([s for s in sessions if s.get('online')]),
            'pending':   len([d for d in devices if d.get('status') == 'pending'])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
    d = request.get_json()
    ip = (d.get('ip') or '').strip()
    if not is_valid_ip(ip): return jsonify({'error': f'Invalid IP address: {ip}'}), 400
    add_to_blacklist(ip, d.get('type', 'temporary'))
    socketio.emit('ip_blocked', {'ip': ip, 'type': d.get('type','temporary'), 'by': session.get('user','admin')})
    return jsonify({'success': True})

@app.route('/api/blacklist/forgive', methods=['POST'])
def api_blacklist_forgive():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    ip = request.get_json()['ip']
    forgive_ip(ip); clear_rate_limit(ip); log_admin('forgive_ip', ip)
    socketio.emit('ip_forgiven', {'ip': ip, 'by': session.get('user','admin')})
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
    d = request.get_json()
    ip = (d.get('ip') or '').strip()
    if not is_valid_ip(ip): return jsonify({'error': f'Invalid IP address: {ip}'}), 400
    label = (d.get('label') or 'New device').strip()[:50]
    add_to_whitelist(ip, label)
    socketio.emit('ip_whitelisted', {'ip': ip, 'label': label, 'by': session.get('user','admin')})
    return jsonify({'success': True})

@app.route('/api/whitelist/remove', methods=['POST'])
def api_whitelist_remove():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    ip = request.get_json()['ip']
    remove_from_whitelist(ip)
    socketio.emit('ip_whitelist_removed', {'ip': ip, 'by': session.get('user','admin')})
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
    d = request.get_json()
    delete_session(d['username'])
    socketio.emit('session_kicked', {'username': d['username']})
    log_admin('kick_session', d['username'])
    return jsonify({'success': True})

@app.route('/api/session/heartbeat', methods=['POST'])
def api_session_heartbeat():
    d         = request.get_json()
    username  = d.get('username', '')
    client_ip = request.remote_addr
    if is_blacklisted(client_ip):
        session.clear(); set_consensus_state(False)
        delete_session(username)
        socketio.emit('session_kicked', {'username': username, 'reason': 'ip_blacklisted'})
        return jsonify({'ok': False, 'kicked': True, 'reason': 'ip_blacklisted'})
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

@app.route('/api/register-device', methods=['POST'])
def api_register_device():
    d         = request.get_json()
    username  = d.get('username', '').strip()
    device_id = d.get('device_id', '').strip()
    pub_key   = d.get('public_key', '').strip()
    label     = str(d.get('label', 'Unknown Device'))[:50].strip()
    client_ip = request.remote_addr
    if not username or not device_id or not pub_key:
        return jsonify({'error': 'registration failed'}), 400
    if not check_dev_rate(client_ip):
        return jsonify({'error': 'Too many registration attempts. Wait an hour or ask admin to redeploy.'}), 429
    if not get_user(username):
        return jsonify({'error': 'registration failed'}), 400
    try:
        jwk = json.loads(pub_key)
        if not all(k in jwk for k in ('kty', 'crv', 'x', 'y')):
            raise ValueError('Missing required JWK fields')
        if jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256':
            raise ValueError('Only EC P-256 keys are accepted')
        import base64 as _b64
        for coord in ('x', 'y'):
            val = jwk[coord]
            pad = 4 - len(val) % 4
            if pad != 4: val += '=' * pad
            decoded = _b64.urlsafe_b64decode(val)
            if len(decoded) != 32:
                raise ValueError(f'Invalid {coord} coordinate length')
    except Exception as e:
        add_log(username, client_ip, 'DENIED', f'Device reg rejected — invalid JWK: {e}')
        return jsonify({'error': 'registration failed'}), 400
    existing = get_device(device_id)
    if existing and existing.get('username') != username:
        add_log(username, client_ip, 'DENIED', f'Device {device_id[:12]} already registered to another user')
        return jsonify({'error': 'registration failed'}), 400
    register_device(username, device_id, pub_key, label, registered_ip=client_ip)
    pending = len(get_pending_devices())
    socketio.emit('device_pending', {'username': username, 'device_id': device_id, 'label': label, 'pending_count': pending})
    add_log(username, client_ip, 'PENDING', f'Device registration pending: {label[:30]}')
    return jsonify({'status': 'pending'})

@app.route('/api/update-ip', methods=['POST'])
def api_update_ip():
    d          = request.get_json()
    username   = d.get('username', '').strip()
    device_id  = d.get('device_id', '').strip()
    device_sig = d.get('device_signature', '')
    device_msg = d.get('device_message', '')
    client_ip  = request.remote_addr
    if not all([username, device_id, device_sig, device_msg]): return jsonify({'error': 'request failed'}), 400
    if not check_dev_rate(client_ip, max_attempts=5): return jsonify({'error': 'request failed'}), 429
    if node4_device_signature({'username': username, 'device_id': device_id, 'device_signature': device_sig, 'device_message': device_msg}) != 'PASS':
        add_log(username, client_ip, 'DENIED', 'IP update — invalid sig')
        return jsonify({'error': 'invalid device signature'}), 403
    dev   = get_device(device_id)
    label = dev['label'] if dev else 'Updated device'
    add_to_whitelist(client_ip, f'{username} ({label[:30]})')
    add_log(username, client_ip, 'GRANTED', 'IP updated via device sig')
    return jsonify({'success': True, 'new_ip': client_ip})

@app.route('/api/device-status')
def api_device_status():
    did = request.args.get('device_id', '')
    if not did: return jsonify({'status': 'unknown'})
    dev = get_device(did)
    return jsonify({'status': dev['status'] if dev else 'not_registered'})

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
    did = request.get_json()['device_id']
    revoked = approve_device(did)
    dev = get_device(did)
    if dev:
        reg_ip = (dev.get('registered_ip') or '').strip()
        if reg_ip:
            add_to_whitelist(normalize_ip(reg_ip), f"{dev['username']} ({dev.get('label','')[:30]}) — auto: device approved")
            socketio.emit('ip_whitelisted', {'ip': reg_ip, 'label': dev['username'], 'by': session.get('user','admin')})
            print(f"[approve] Auto-whitelisted {reg_ip} for {dev['username']}")
        else:
            print(f"[approve] WARNING: no registered_ip for device {did[:12]} — whitelist not updated")
    socketio.emit('device_approved', {'device_id': did, 'username': dev['username'] if dev else ''})
    for revoked_id in revoked:
        socketio.emit('device_revoked', {'device_id': revoked_id, 'reason': f'Superseded by new device approval for {dev["username"] if dev else ""}'})
        _notify_guard(f"🔄 Device {revoked_id[:12]}... revoked — {dev['username'] if dev else ''} approved a new device")
    log_admin('approve_device', f"{did} (revoked {len(revoked)} old device(s))")
    return jsonify({'success': True, 'revoked': revoked})

@app.route('/api/devices/reject', methods=['POST'])
def api_device_reject():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    did = request.get_json()['device_id']
    dev = get_device(did)
    reject_device(did)
    socketio.emit('device_rejected', {'device_id': did, 'username': dev['username'] if dev else ''})
    return jsonify({'success': True})

@app.route('/api/devices/delete', methods=['POST'])
def api_device_delete():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    did = request.get_json()['device_id']
    dev = get_device(did)
    delete_device(did)
    socketio.emit('device_revoked', {'device_id': did, 'username': dev['username'] if dev else '', 'reason': 'manually revoked'})
    return jsonify({'success': True})

@app.route('/api/users')
def api_get_users():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    from database import get_cursor as _gc
    with get_db() as conn:
        cur = _gc(conn)
        cur.execute("SELECT username, role FROM users ORDER BY username")
        return jsonify([dict(r) for r in cur.fetchall()])

@app.route('/api/users/add', methods=['POST'])
def api_add_user():
    if 'user' not in session: return jsonify({'error': 'unauthorized'}), 401
    d        = request.get_json()
    username = d.get('username', '').strip()[:50]
    password = d.get('password', '')[:128]
    role     = d.get('role', 'Security Officer')[:50]
    if not username or not password: return jsonify({'error': 'Username and password required'}), 400
    if not is_valid_username(username): return jsonify({'error': 'Username must be 3-50 chars, letters/numbers/underscore only'}), 400
    if not is_valid_password(password): return jsonify({'error': 'Password must be at least 8 characters'}), 400
    import bcrypt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    try:
        from database import get_cursor as _gc
        with get_db() as conn:
            cur = _gc(conn)
            cur.execute("INSERT INTO users (username, password_hash, role, display_name) VALUES (%s,%s,%s,%s) ON CONFLICT (username) DO NOTHING",
                        (username, hashed, role, username))
            if cur.rowcount == 0: return jsonify({'error': 'username already exists'}), 409
        log_admin('add_user', username)
        with _valid_users_lock: _valid_users_cache['ts'] = 0
        socketio.emit('user_added', {'username': username, 'role': role, 'by': session.get('user','admin')})
        return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)}), 500

# ── EMERGENCY BREAK-GLASS ──
_em_used     = False
_em_used_at  = 0
_em_cooldown = 300

def _emergency_handler():
    global _em_used, _em_used_at
    em_pw  = os.environ.get('EMERGENCY_PASSWORD', '')
    em_ip  = os.environ.get('EMERGENCY_ALLOWED_IP', '')
    client = request.remote_addr
    if not em_pw: return jsonify({'error': 'not found'}), 404
    if em_ip and client != em_ip: return jsonify({'error': 'not found'}), 404
    if _em_used: return jsonify({'error': 'key already consumed — redeploy to reset'}), 429
    now = time.time()
    if now - _em_used_at < _em_cooldown:
        return jsonify({'error': f'cooldown — wait {int(_em_cooldown-(now-_em_used_at))}s'}), 429
    d = request.get_json() or {}
    if d.get('password') != em_pw:
        _em_used_at = now
        add_log('EMERGENCY', client, 'DENIED', 'Wrong password')
        return jsonify({'error': 'unauthorized'}), 401
    _em_used = True; _em_used_at = now
    delete_session('admin')
    create_session('admin', client, 'Emergency Admin', secrets.token_hex(32))
    session['user'] = 'admin'
    set_consensus_state(True)
    add_to_whitelist(client, 'Emergency re-entry')
    forgive_ip(client); clear_rate_limit(client)
    socketio.emit('chat_message', {'role': 'system', 'message': f'🚨 EMERGENCY ACCESS from {mask_ip(client)} — key consumed.'})
    add_log('admin', client, 'EMERGENCY', 'Break-glass used — key consumed')
    return jsonify({'granted': True, 'message': 'Emergency access granted. Key disabled. Go to /dashboard.'})

_em_path = os.environ.get('EMERGENCY_PATH', 'emergency-access')
app.add_url_rule(f'/api/{_em_path}', 'emergency_access', _emergency_handler, methods=['POST'])

# ── MAIN ──
if __name__ == '__main__':
    print("NETAD Security System starting...")
    threading.Thread(target=token_cleanup_worker, daemon=True).start()
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    socketio.run(app, host=host, port=port, debug=False)
