import socket
import json
import threading
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()
from database import is_whitelisted
 
def validate(payload):
    # Allow bypassing whitelist via env var (useful for first Railway deploy)
    if os.environ.get('DISABLE_IP_WHITELIST', 'false').lower() == 'true':
        print(f"Node 3 PASS: IP whitelist disabled via env var")
        return 'PASS'

    client_ip = payload.get('ip', '')
    if is_whitelisted(client_ip):
        print(f"Node 3 PASS: {client_ip} is whitelisted")
        return 'PASS'
    print(f"Node 3 FAIL: {client_ip} not in whitelist")
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
        print(f"Node 3 error: {e}")
        conn.send(b'FAIL')
    finally:
        conn.close()
 
def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', 5003))
    server.listen(10)
    print("Node 3 (IP whitelist) listening on port 5003...")
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn,))
        t.start()
 
if __name__ == '__main__':
    start()