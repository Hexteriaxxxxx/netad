# nodes/node1.py — Password Verification Node
# Reads credentials from the PostgreSQL database (single source of truth).
# Uses bcrypt for secure password verification.

import socket
import json
import threading
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()

import bcrypt
from database import get_user

def validate(payload):
    username = payload.get('username', '')
    password = payload.get('password', '')

    if not username or not password:
        print("Node 1 FAIL: missing credentials")
        return 'FAIL'

    try:
        user = get_user(username)
        if not user:
            print(f"Node 1 FAIL: user '{username}' not found")
            return 'FAIL'

        stored_hash = user['password_hash']

        # Support both bcrypt hashes and legacy SHA-256 hashes
        # bcrypt hashes start with $2b$ or $2a$
        if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$'):
            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                print(f"Node 1 PASS: {username} (bcrypt)")
                return 'PASS'
        else:
            # Legacy SHA-256 fallback
            import hashlib
            hashed_input = hashlib.sha256(password.encode()).hexdigest()
            if stored_hash == hashed_input:
                print(f"Node 1 PASS: {username} (sha256 legacy)")
                return 'PASS'

        print(f"Node 1 FAIL: wrong password for '{username}'")
        return 'FAIL'

    except Exception as e:
        print(f"Node 1 FAIL: database error — {e}")
        return 'FAIL'

def handle_client(conn):
    try:
        data = conn.recv(4096).decode()
        payload = json.loads(data)
        if payload.get('type') == 'heartbeat':
            conn.send(b'ALIVE')
        else:
            result = validate(payload)
            conn.send(result.encode())
    except Exception as e:
        print(f"Node 1 error: {e}")
        conn.send(b'FAIL')
    finally:
        conn.close()

def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', 5001))
    server.listen(10)
    print("Node 1 (password bcrypt) listening on port 5001...")
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn,))
        t.start()

if __name__ == '__main__':
    start()
