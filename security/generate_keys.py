# security/generate_keys.py
# Run ONCE to set up keys and seed the database.
# Usage: python security/generate_keys.py
# Passwords are loaded from environment variables — never hardcoded.

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import bcrypt
import base64
import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

# ── Generate RSA key pair ──
print("Generating RSA-2048 key pair...")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

os.makedirs('security', exist_ok=True)

with open('security/private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open('security/public_key.pem', 'wb') as f:
    f.write(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("RSA keys written to security/private_key.pem and security/public_key.pem")

# ── Print base64-encoded keys for Railway environment variables ──
with open('security/private_key.pem', 'rb') as f:
    private_b64 = base64.b64encode(f.read()).decode()
with open('security/public_key.pem', 'rb') as f:
    public_b64 = base64.b64encode(f.read()).decode()

print("\n" + "="*60)
print("RAILWAY ENV VARS — copy these into your Railway dashboard:")
print("="*60)
print(f"RSA_PRIVATE_KEY_B64={private_b64}")
print(f"RSA_PUBLIC_KEY_B64={public_b64}")
print("="*60 + "\n")

# ── Seed users ──
# Passwords must be set as environment variables in .env
# Example .env entries:
#   PASSWORD_ADMIN=your_secure_password_here
#   PASSWORD_KEVIN=another_secure_password
users = [
    ('admin',  os.environ.get('PASSWORD_ADMIN',  'changeme_admin'),  'Project Manager',   'Gian Admin'),
    ('kevin',  os.environ.get('PASSWORD_KEVIN',  'changeme_kevin'),  'Lead Dev',          'Kevin Lead'),
    ('josiah', os.environ.get('PASSWORD_JOSIAH', 'changeme_josiah'), 'Co-Lead Dev',       'Josiah Dev'),
    ('jm',     os.environ.get('PASSWORD_JM',     'changeme_jm'),     'Node Dev A',        'JM Node'),
    ('karl',   os.environ.get('PASSWORD_KARL',   'changeme_karl'),   'Security Designer', 'Karl Security'),
    ('nico',   os.environ.get('PASSWORD_NICO',   'changeme_nico'),   'Multi-role',        'Nico Dev'),
    ('lj',     os.environ.get('PASSWORD_LJ',     'changeme_lj'),     'Node Dev B',        'LJ Node'),
]

print("\nSeeding users with bcrypt-hashed passwords...")
conn = psycopg2.connect(os.environ['DATABASE_URL'])
cur = conn.cursor()

for username, password, role, display_name in users:
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    cur.execute('''
        INSERT INTO users (username, password_hash, role, display_name)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (username) DO UPDATE
        SET password_hash = EXCLUDED.password_hash,
            role = EXCLUDED.role,
            display_name = EXCLUDED.display_name
    ''', (username, hashed, role, display_name))
    print(f"  Seeded user: {username} ({role})")

conn.commit()
conn.close()
print("Users seeded with bcrypt hashes.")

# ── Seed whitelist ──
print("\nSeeding default whitelist...")
conn = psycopg2.connect(os.environ['DATABASE_URL'])
cur = conn.cursor()

whitelist = [
    ('127.0.0.1',    'Localhost'),
    ('192.168.1.5',  'Admin laptop (Gian)'),
    ('192.168.1.6',  'Kevin laptop'),
    ('192.168.1.7',  'JM laptop'),
    ('192.168.1.8',  'Karl laptop'),
    ('192.168.1.9',  'Josiah laptop'),
    ('192.168.1.10', 'LJ laptop'),
    ('192.168.1.11', 'Nico laptop'),
]

for ip, label in whitelist:
    cur.execute('''
        INSERT INTO whitelist (ip, label)
        VALUES (%s, %s)
        ON CONFLICT (ip) DO NOTHING
    ''', (ip, label))
    print(f"  Whitelisted: {ip} ({label})")

conn.commit()
conn.close()
print("\nSetup complete! You can now run: python main.py")
