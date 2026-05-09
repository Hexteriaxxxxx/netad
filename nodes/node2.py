import socket
import json
import time
import threading

EXPIRY_SECONDS = 30  # Request expires after 30 seconds

def validate(payload):
    request_time = payload.get('timestamp', 0)
    current_time = time.time()
    age = current_time - request_time

    if age > EXPIRY_SECONDS:
        print(f"Node 2 FAIL: request too old ({age:.1f}s)")
        return 'FAIL'
    elif age < 0:
        print(f"Node 2 FAIL: future timestamp detected")
        return 'FAIL'
    else:
        print(f"Node 2 PASS: timestamp fresh ({age:.1f}s old)")
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
        print(f"Node 2 error: {e}")
        conn.send(b'FAIL')
    finally:
        conn.close()

def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', 5002))
    server.listen(10)
    print("Node 2 (timestamp) listening on port 5002...")
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn,))
        t.start()

if __name__ == '__main__':
    start()