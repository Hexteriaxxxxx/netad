# security/signer.py
# RSA-PSS signing and verification for NETAD Security System
# Loads keys from PEM files (local) or from environment variables (Railway/cloud)

import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PRIVATE_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'private_key.pem')
PUBLIC_KEY_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'public_key.pem')


def _load_private_key():
    # Try env var first (Railway/cloud), fall back to file (local dev)
    key_b64 = os.environ.get('RSA_PRIVATE_KEY_B64')
    if key_b64:
        key_pem = base64.b64decode(key_b64)
    elif os.path.exists(PRIVATE_KEY_PATH):
        with open(PRIVATE_KEY_PATH, 'rb') as f:
            key_pem = f.read()
    else:
        raise RuntimeError(
            "RSA private key not found. Set RSA_PRIVATE_KEY_B64 env var "
            "or run: python security/generate_keys.py"
        )
    return serialization.load_pem_private_key(key_pem, password=None)


def _load_public_key():
    # Try env var first (Railway/cloud), fall back to file (local dev)
    key_b64 = os.environ.get('RSA_PUBLIC_KEY_B64')
    if key_b64:
        key_pem = base64.b64decode(key_b64)
    elif os.path.exists(PUBLIC_KEY_PATH):
        with open(PUBLIC_KEY_PATH, 'rb') as f:
            key_pem = f.read()
    else:
        raise RuntimeError(
            "RSA public key not found. Set RSA_PUBLIC_KEY_B64 env var "
            "or run: python security/generate_keys.py"
        )
    return serialization.load_pem_public_key(key_pem)


def sign_request(message: str) -> str:
    """
    Sign a message string with the RSA private key using PSS padding.
    Returns a base64-encoded signature string.
    """
    private_key = _load_private_key()
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(message: str, signature_b64: str) -> bool:
    """
    Verify a base64-encoded RSA-PSS signature against the public key.
    Returns True if valid, False otherwise.
    """
    try:
        public_key = _load_public_key()
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
