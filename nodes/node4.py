# nodes/node4.py — Device Signature Node (ECDSA P-256 via Web Crypto API)

import socket, json, threading, sys, os, base64
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()

def p1363_to_der(sig_bytes):
    r, s = sig_bytes[:32], sig_bytes[32:]
    def enc(n):
        n = n.lstrip(b'\x00') or b'\x00'
        if n[0] & 0x80: n = b'\x00' + n
        return bytes([0x02, len(n)]) + n
    r_enc, s_enc = enc(r), enc(s)
    body = r_enc + s_enc
    return bytes([0x30, len(body)]) + body

def jwk_to_public_key(jwk_str):
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1
    jwk = json.loads(jwk_str)
    def b64u(s):
        pad = 4 - len(s) % 4
        if pad != 4: s += '=' * pad
        return int.from_bytes(base64.urlsafe_b64decode(s), 'big')
    return EllipticCurvePublicNumbers(x=b64u(jwk['x']), y=b64u(jwk['y']), curve=SECP256R1()).public_key()

def validate(payload):
    username  = payload.get('username', '')
    device_id = payload.get('device_id', '')
    sig_b64   = payload.get('device_signature', '')
    message   = payload.get('device_message', '')
    if not all([username, device_id, sig_b64, message]):
        print("Node 4 FAIL: missing device auth fields")
        return 'FAIL'
    try:
        from database import get_device_public_key
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives import hashes
        pub_jwk = get_device_public_key(username, device_id)
        if not pub_jwk:
            print(f"Node 4 FAIL: device not approved for '{username}'")
            return 'FAIL'
        pub_key = jwk_to_public_key(pub_jwk)
        sig_der = p1363_to_der(base64.b64decode(sig_b64))
        pub_key.verify(sig_der, message.encode(), ECDSA(hashes.SHA256()))
        print(f"Node 4 PASS: ECDSA valid for '{username}' device '{device_id[:8]}...'")
        return 'PASS'
    except Exception as e:
        print(f"Node 4 FAIL: {e}")
        return 'FAIL'

def handle_client(conn):
    try:
        data = conn.recv(4096).decode()
        payload = json.loads(data)
        if payload.get('type') == 'heartbeat':
            conn.send(b'ALIVE')
        else:
            conn.send(validate(payload).encode())
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
    print("Node 4 (ECDSA device signature) listening on port 5004...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn,)).start()

if __name__ == '__main__':
    start()
