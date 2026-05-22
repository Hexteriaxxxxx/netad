# database.py
# Central database manager for NETAD Security System

import os
import re
import ipaddress
import psycopg2
import psycopg2.extras
import psycopg2.pool
from contextlib import contextmanager
from dotenv import load_dotenv
import threading
import time

load_dotenv()

def get_database_url():
    return os.environ.get('DATABASE_URL', 'postgresql://postgres:yourpassword@localhost:5432/netad')

# ══════════════════════════════════════════════════
# CONNECTION POOL
# Reuses existing DB connections instead of creating a new TCP
# connection on every request. Cuts response time significantly.
# ══════════════════════════════════════════════════
_pool: psycopg2.pool.ThreadedConnectionPool = None
_pool_lock = threading.Lock()

def _get_pool():
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                try:
                    _pool = psycopg2.pool.ThreadedConnectionPool(
                        minconn=2, maxconn=10, dsn=get_database_url()
                    )
                    print('[DB] Connection pool initialized (2-10 connections)')
                except Exception as e:
                    print(f'[DB] Pool init failed: {e}')
                    raise
    return _pool

@contextmanager
def get_db():
    pool = _get_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        pool.putconn(conn)

def get_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

# ══════════════════════════════════════════════════
# INPUT VALIDATION
# ══════════════════════════════════════════════════
def normalize_ip(ip: str) -> str:
    """Normalize IP — strips IPv6-mapped IPv4 prefix and zone IDs."""
    if not ip: return ip
    ip = ip.strip()
    if ip.startswith('::ffff:'): ip = ip[7:]
    if ip.startswith('::FFFF:'): ip = ip[7:]
    if '%' in ip: ip = ip.split('%')[0]
    return ip

def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 or IPv6 address."""
    if not ip: return False
    try:
        ipaddress.ip_address(normalize_ip(ip.strip()))
        return True
    except ValueError:
        return False

def is_valid_username(username: str) -> bool:
    """3-50 chars, alphanumeric + underscore only."""
    return bool(username and 3 <= len(username) <= 50 and re.match(r'^[a-zA-Z0-9_]+$', username))

def is_valid_password(password: str) -> bool:
    """Minimum 8 characters."""
    return bool(password and len(password) >= 8)

# ══════════════════════════════════════════════════
# IN-MEMORY CACHE — whitelist + blacklist
# Prevents DB connection timeouts during parallel node consensus
# Refreshes every 30 seconds automatically
# ══════════════════════════════════════════════════
_wl_cache: set = set()
_bl_cache: set = set()
_cache_lock = threading.Lock()
_cache_ts   = 0.0
_CACHE_TTL  = 30  # seconds

def _refresh_cache(force=False):
    global _wl_cache, _bl_cache, _cache_ts
    now = time.time()
    with _cache_lock:
        if not force and now - _cache_ts < _CACHE_TTL:
            return
    try:
        with get_db() as conn:
            cur = get_cursor(conn)
            cur.execute("SELECT ip FROM whitelist")
            wl = {row['ip'] for row in cur.fetchall()}
            cur.execute(
                "SELECT ip FROM blacklist WHERE type = 'permanent' OR blocked_until > NOW()"
            )
            bl = {row['ip'] for row in cur.fetchall()}
        with _cache_lock:
            _wl_cache  = wl
            _bl_cache  = bl
            _cache_ts  = now
    except Exception as e:
        print(f"[Cache] refresh error: {e}")

def invalidate_cache():
    """Call after any whitelist/blacklist write so next check re-fetches immediately."""
    global _cache_ts
    with _cache_lock:
        _cache_ts = 0.0

# ── USERS ──
def get_user(username):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        return cur.fetchone()

def verify_password(username, password):
    import bcrypt, hashlib
    user = get_user(username)
    if not user: return False
    stored = user['password_hash']
    if stored.startswith('$2b$') or stored.startswith('$2a$'):
        return bcrypt.checkpw(password.encode(), stored.encode())
    return stored == hashlib.sha256(password.encode()).hexdigest()

# ── WHITELIST ──
def is_whitelisted(ip):
    ip = normalize_ip(ip)
    _refresh_cache()
    with _cache_lock:
        return ip in _wl_cache

def get_whitelist():
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT * FROM whitelist ORDER BY created_at DESC")
        return cur.fetchall()

def add_to_whitelist(ip, label='Unknown device'):
    ip = normalize_ip(ip)
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            "INSERT INTO whitelist (ip, label) VALUES (%s, %s) ON CONFLICT (ip) DO NOTHING",
            (ip, label)
        )
    invalidate_cache()

def remove_from_whitelist(ip):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM whitelist WHERE ip = %s", (ip,))
    invalidate_cache()

# ── BLACKLIST ──
def is_blacklisted(ip):
    ip = normalize_ip(ip)
    _refresh_cache()
    with _cache_lock:
        return ip in _bl_cache

def get_blacklist():
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("""
            SELECT *, EXTRACT(EPOCH FROM (blocked_until - NOW()))::int AS seconds_remaining
            FROM blacklist ORDER BY created_at DESC
        """)
        return cur.fetchall()

def add_to_blacklist(ip, block_type='temporary', duration_seconds=1800):
    from datetime import datetime, timedelta
    blocked_until = None
    if block_type == 'temporary':
        blocked_until = datetime.now() + timedelta(seconds=duration_seconds)
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            """
            INSERT INTO blacklist (ip, type, blocked_until) VALUES (%s, %s, %s)
            ON CONFLICT (ip) DO UPDATE SET type = EXCLUDED.type, blocked_until = EXCLUDED.blocked_until
            """,
            (ip, block_type, blocked_until)
        )
    invalidate_cache()

def forgive_ip(ip):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM blacklist WHERE ip = %s", (ip,))
    invalidate_cache()

# ── LOGS ──
def add_log(username, ip, result, reason=''):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            "INSERT INTO logs (username, ip, result, reason) VALUES (%s, %s, %s, %s)",
            (username, ip, result, reason)
        )

def get_logs(limit=50):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT %s", (limit,))
        return cur.fetchall()

def get_logs_today(limit=50):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            """
            SELECT * FROM logs
            WHERE timestamp >= date_trunc('day', NOW() AT TIME ZONE 'Asia/Manila') AT TIME ZONE 'Asia/Manila'
            ORDER BY timestamp DESC LIMIT %s
            """,
            (limit,)
        )
        return cur.fetchall()

def get_logs_today_count():
    """Returns actual total count of today's logs — not capped by display limit."""
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            """
            SELECT COUNT(*) as c FROM logs
            WHERE timestamp >= date_trunc('day', NOW() AT TIME ZONE 'Asia/Manila') AT TIME ZONE 'Asia/Manila'
            """
        )
        return cur.fetchone()['c']

# ── SESSIONS ──
def create_session(username, ip, role, token):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM sessions WHERE username = %s", (username,))
        cur.execute(
            """
            INSERT INTO sessions (username, ip, role, token, last_seen)
            VALUES (%s, %s, %s, %s, NOW())
            """,
            (username, ip, role, token)
        )

def update_session_heartbeat(username):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("UPDATE sessions SET last_seen = NOW() WHERE username = %s", (username,))

def get_sessions():
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("""
            SELECT *,
                CASE WHEN last_seen > NOW() - INTERVAL '60 seconds' THEN true ELSE false END AS online
            FROM sessions ORDER BY last_seen DESC
        """)
        return cur.fetchall()

def delete_session(username):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM sessions WHERE username = %s", (username,))

def delete_all_sessions():
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM sessions")

# ── SESSION TOKENS ──
def claim_token(token: str) -> bool:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO used_tokens (token) VALUES (%s) ON CONFLICT (token) DO NOTHING",
            (token,)
        )
        return cur.rowcount == 1

def is_token_used(token):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT id FROM used_tokens WHERE token = %s", (token,))
        return cur.fetchone() is not None

def mark_token_used(token):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("INSERT INTO used_tokens (token) VALUES (%s) ON CONFLICT DO NOTHING", (token,))

def cleanup_used_tokens():
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM used_tokens WHERE used_at < NOW() - INTERVAL '30 minutes'")

# ── AI LOGS ──
def add_ai_log(ip, username, description, score, flagged):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            "INSERT INTO ai_logs (ip, username, description, score, flagged) VALUES (%s, %s, %s, %s, %s)",
            (ip, username, description, float(score), flagged)
        )

def get_ai_logs(limit=20):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT * FROM ai_logs ORDER BY timestamp DESC LIMIT %s", (limit,))
        return cur.fetchall()

# ── RATE LIMITING ──
def get_attempt_count(ip):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            "SELECT COUNT(*) as count FROM logs WHERE ip = %s AND result = 'DENIED' AND timestamp > NOW() - INTERVAL '1 hour'",
            (ip,)
        )
        result = cur.fetchone()
        return result['count'] if result else 0

def get_all_failed_count(ip):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            "SELECT COUNT(*) as count FROM logs WHERE ip = %s AND result != 'GRANTED' AND timestamp > NOW() - INTERVAL '1 hour'",
            (ip,)
        )
        result = cur.fetchone()
        return result['count'] if result else 0

def clear_rate_limit(ip):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM logs WHERE ip = %s AND result IN ('DENIED', 'SUSPICIOUS')", (ip,))
        cur.execute("DELETE FROM blacklist WHERE ip = %s", (ip,))
    invalidate_cache()
    return True

# ── CHAT LOGS ──
def add_chat_log(role, message, sender=''):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("INSERT INTO chat_logs (role, message, sender) VALUES (%s, %s, %s)", (role, message, sender))

def get_chat_logs(limit=50):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT * FROM chat_logs ORDER BY timestamp DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        return list(reversed(rows))

# ── DEVICE KEYS ──
def register_device(username, device_id, public_key_jwk, label='Unknown Device', registered_ip=''):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("""
            INSERT INTO device_keys (username, device_id, public_key, label, status, registered_ip)
            VALUES (%s, %s, %s, %s, 'pending', %s)
            ON CONFLICT (device_id) DO UPDATE
            SET public_key = EXCLUDED.public_key,
                username = EXCLUDED.username,
                registered_ip = EXCLUDED.registered_ip
        """, (username, device_id, public_key_jwk, label, registered_ip))

def get_device(device_id):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT * FROM device_keys WHERE device_id = %s", (device_id,))
        return cur.fetchone()

def get_device_public_key(username, device_id):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            "SELECT public_key FROM device_keys WHERE username = %s AND device_id = %s AND status = 'approved'",
            (username, device_id)
        )
        row = cur.fetchone()
        return row['public_key'] if row else None

def get_all_devices():
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT * FROM device_keys ORDER BY created_at DESC")
        return cur.fetchall()

def get_pending_devices():
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT * FROM device_keys WHERE status = 'pending' ORDER BY created_at DESC")
        return cur.fetchall()

def approve_device(device_id):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT username FROM device_keys WHERE device_id = %s", (device_id,))
        row = cur.fetchone()
        if not row: return []
        username = row['username']
        cur.execute(
            "SELECT device_id FROM device_keys WHERE username = %s AND status = 'approved' AND device_id != %s",
            (username, device_id)
        )
        revoked = [r['device_id'] for r in cur.fetchall()]
        cur.execute(
            "UPDATE device_keys SET status = 'revoked' WHERE username = %s AND status = 'approved' AND device_id != %s",
            (username, device_id)
        )
        cur.execute(
            "UPDATE device_keys SET status = 'approved', approved_at = NOW() WHERE device_id = %s",
            (device_id,)
        )
        return revoked

def reject_device(device_id):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("UPDATE device_keys SET status = 'rejected' WHERE device_id = %s", (device_id,))

def delete_device(device_id):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM device_keys WHERE device_id = %s", (device_id,))

# ── TEST CONNECTION ──
if __name__ == '__main__':
    print("Testing database connection...")
    try:
        with get_db() as conn:
            cur = get_cursor(conn)
            cur.execute("SELECT version()")
            version = cur.fetchone()
            print(f"Connected! PostgreSQL: {str(version['version'])[:40]}...")
    except Exception as e:
        print(f"Connection failed: {e}")
