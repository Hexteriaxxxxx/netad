# nodes/node5.py — Session Token Node (atomic TOCTOU-safe)

import socket
import json
import threading
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()

from database import claim_token

def validate(payload):
    token = payload.get('session_token', '')
    if not token:
        print("Node 5 FAIL: no session token provided")
        return 'FAIL'

    # claim_token does an atomic INSERT — returns True only if this
    # is the first time this token is seen (TOCTOU-safe)
    if claim_token(token):
        print(f"Node 5 PASS: token claimed successfully")
        return 'PASS'
    else:
        print(f"Node 5 FAIL: token already used or invalid")
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
        print(f"Node 5 error: {e}")
        conn.send(b'FAIL')
    finally:
        conn.close()

def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', 5005))
    server.listen(10)
    print("Node 5 (session token atomic) listening on port 5005...")
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn,))
        t.start()

if __name__ == '__main__':
    start()
