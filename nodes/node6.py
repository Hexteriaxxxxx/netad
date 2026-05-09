# nodes/node6.py — Rate Limiting Node (counts ALL failed/suspicious attempts)

import socket
import json
import threading
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()

from database import get_all_failed_count, add_to_blacklist, is_blacklisted

MAX_ATTEMPTS = 5  # raised from 3 to reduce false lockouts

def validate(payload):
    ip = payload.get('ip', 'unknown')

    if is_blacklisted(ip):
        print(f"Node 6 FAIL: {ip} is blacklisted")
        return 'FAIL'

    # Count ALL non-GRANTED results (DENIED + SUSPICIOUS) in last hour
    count = get_all_failed_count(ip)
    if count >= MAX_ATTEMPTS:
        add_to_blacklist(ip, 'temporary', 1800)
        print(f"Node 6 FAIL: {ip} rate limited ({count} failed attempts in last hour)")
        return 'FAIL'

    print(f"Node 6 PASS: {ip} — {count}/{MAX_ATTEMPTS} failed attempts")
    return 'PASS'

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
        print(f"Node 6 error: {e}")
        conn.send(b'FAIL')
    finally:
        conn.close()

def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', 5006))
    server.listen(10)
    print("Node 6 (rate limiting) listening on port 5006...")
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn,))
        t.start()

if __name__ == '__main__':
    start()
