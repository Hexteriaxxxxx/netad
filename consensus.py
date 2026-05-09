# consensus.py
import socket
import threading
import json

NODES = [
    ('localhost', 5001),  # Node 1 - password hash
    ('localhost', 5002),  # Node 2 - timestamp
    ('localhost', 5003),  # Node 3 - IP whitelist
    ('localhost', 5004),  # Node 4 - digital signature
    ('localhost', 5005),  # Node 5 - session token
    ('localhost', 5006),  # Node 6 - rate limiting
]

def ask_node(host, port, payload, results, index):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        s.send(json.dumps(payload).encode())
        response = s.recv(1024).decode()
        results[index] = response.strip()
        s.close()
    except Exception as e:
        results[index] = 'FAIL'
        print(f"Node {index+1} error: {e}")

def get_consensus(payload):
    results = [None] * len(NODES)
    threads = []

    for i, (host, port) in enumerate(NODES):
        t = threading.Thread(
            target=ask_node,
            args=(host, port, payload, results, i)
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=6)

    print(f"Node votes: {results}")

    if all(r == 'PASS' for r in results):
        return 'GRANTED', results
    else:
        return 'DENIED', results

def check_heartbeat():
    alive = []
    for i, (host, port) in enumerate(NODES):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((host, port))
            s.send(json.dumps({'type': 'heartbeat'}).encode())
            s.recv(1024)
            s.close()
            alive.append(True)
        except:
            alive.append(False)
    return alive