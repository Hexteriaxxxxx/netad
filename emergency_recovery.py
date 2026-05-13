"""
NETAD Emergency Recovery Script
================================
Run this if your entire team is locked out of the system.
This will:
  1. Clear all blacklisted IPs
  2. Re-approve your device
  3. Re-whitelist your IP
  4. Clear all failed login logs

Usage:
  python emergency_recovery.py
"""
import psycopg2, urllib.request, os

DB = 'postgresql://postgres:ZUGxNBOxblwoYPVwCGQmJgBJNdWqBIBX@viaduct.proxy.rlwy.net:57649/railway'

print("NETAD Emergency Recovery")
print("=" * 40)

conn = psycopg2.connect(DB)
cur = conn.cursor()

# 1. Clear blacklist
cur.execute("DELETE FROM blacklist")
print(f"✓ Cleared blacklist ({cur.rowcount} entries removed)")

# 2. Clear failed login logs
cur.execute("DELETE FROM logs WHERE result IN ('DENIED', 'SUSPICIOUS')")
print(f"✓ Cleared failed login logs ({cur.rowcount} entries removed)")

# 3. Get your current IP and whitelist it
my_ip = urllib.request.urlopen('https://api.ipify.org').read().decode()
cur.execute("""
    INSERT INTO whitelist (ip, label)
    VALUES (%s, 'Emergency recovery')
    ON CONFLICT (ip) DO UPDATE SET label = 'Emergency recovery'
""", (my_ip,))
print(f"✓ Whitelisted your IP: {my_ip}")

# 4. Re-approve all devices for your team
cur.execute("""
    UPDATE device_keys SET status = 'approved', approved_at = NOW()
    WHERE status = 'rejected'
""")
print(f"✓ Re-approved {cur.rowcount} rejected device(s)")

# 5. Clear used tokens (fresh start)
cur.execute("DELETE FROM used_tokens")
print(f"✓ Cleared used tokens")

conn.commit()
conn.close()

print("=" * 40)
print("Recovery complete!")
print(f"Your IP ({my_ip}) is now whitelisted.")
print("All rejected devices are re-approved.")
print("Open the site and log in normally.")
print()
print("If you still can't log in, use the emergency endpoint:")
print("  POST /api/emergency-access")
print("  Body: {\"password\": \"<your EMERGENCY_PASSWORD from Railway>\"}")
