# database.py
# Central database manager for NETAD Security System

import os
import psycopg2
import psycopg2.extras
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()

def get_database_url():
    return os.environ.get('DATABASE_URL', 'postgresql://postgres:yourpassword@localhost:5432/netad')

@contextmanager
def get_db():
    conn = psycopg2.connect(get_database_url())
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

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
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT id FROM whitelist WHERE ip = %s", (ip,))
        return cur.fetchone() is not None

def get_whitelist():
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("SELECT * FROM whitelist ORDER BY created_at DESC")
        return cur.fetchall()

def add_to_whitelist(ip, label='Unknown device'):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            "INSERT INTO whitelist (ip, label) VALUES (%s, %s) ON CONFLICT (ip) DO NOTHING",
            (ip, label)
        )

def remove_from_whitelist(ip):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM whitelist WHERE ip = %s", (ip,))

# ── BLACKLIST ──
def is_blacklisted(ip):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            "SELECT id FROM blacklist WHERE ip = %s AND (type = 'permanent' OR blocked_until > NOW())",
            (ip,)
        )
        return cur.fetchone() is not None

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

def forgive_ip(ip):
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM blacklist WHERE ip = %s", (ip,))

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
    """Get logs from today only — resets at midnight."""
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute(
            """
            SELECT * FROM logs
            WHERE timestamp >= CURRENT_DATE
            ORDER BY timestamp DESC LIMIT %s
            """,
            (limit,)
        )
        return cur.fetchall()

# ── SESSIONS ──
def create_session(username, ip, role, token):
    """
    Create a session for a user.
    ENFORCES ONE SESSION PER USERNAME:
    - Deletes ALL existing sessions for this username first
    - Then inserts the new session
    - Broadcasts kick to old session via socketio (handled in main.py before calling this)
    """
    with get_db() as conn:
        cur = get_cursor(conn)
        # Hard delete ALL rows for this username — no duplicates possible
        cur.execute("DELETE FROM sessions WHERE username = %s", (username,))
        # Insert fresh session
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
    """Delete ALL sessions for a username — ensures complete cleanup."""
    with get_db() as conn:
        cur = get_cursor(conn)
        cur.execute("DELETE FROM sessions WHERE username = %s", (username,))

def delete_all_sessions():
    """Emergency — wipe ALL active sessions."""
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
        cur.execute(
            "UPDATE device_keys SET status = 'approved', approved_at = NOW() WHERE device_id = %s",
            (device_id,)
        )

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
