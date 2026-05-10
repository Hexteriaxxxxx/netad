import psycopg2

conn = psycopg2.connect('postgresql://postgres:ZUGxNBOxblwoYPVwCGQmJgBJNdWqBIBX@viaduct.proxy.rlwy.net:57649/railway')
cur = conn.cursor()

# Remove local IPs, keep only real ones
cur.execute("DELETE FROM whitelist WHERE ip LIKE '192.168.%' OR ip = '127.0.0.1'")
print(f"Removed {cur.rowcount} local IPs from whitelist")

# Clear old logs and blacklist for clean demo
cur.execute("DELETE FROM blacklist")
cur.execute("DELETE FROM logs")
cur.execute("DELETE FROM used_tokens")
print("Cleared blacklist, logs, used tokens")

conn.commit()
conn.close()
print("Done! Ready for demo.")
