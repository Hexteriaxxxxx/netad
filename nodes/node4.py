# nodes/node4.py — Digital Signature Node (RSA-PSS)

import socket
import json
import threading
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def validate(payload):
    signature_b64 = payload.get('signature', '')
    message = payload.get('hash', '')

    if not signature_b64:
        print("Node 4 FAIL: no signature provided")
        return 'FAIL'

    if not message:
        print("Node 4 FAIL: no hash/message to verify")
        return 'FAIL'

    try:
        from security.signer import verify_signature
        if verify_signature(message, signature_b64):
            print("Node 4 PASS: RSA-PSS signature valid")
            return 'PASS'
        else:
            print("Node 4 FAIL: signature verification failed")
            return 'FAIL'
    except Exception as e:
        print(f"Node 4 FAIL: error during verification — {e}")
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
        print(f"Node 4 error: {e}")
        conn.send(b'FAIL')
    finally:
        conn.close()

def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', 5004))
    server.listen(10)
    print("Node 4 (digital signature RSA-PSS) listening on port 5004...")
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn,))
        t.start()

if __name__ == '__main__':
    start()
