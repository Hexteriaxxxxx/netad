import os
import psycopg2
from dotenv import load_dotenv
load_dotenv()

conn = psycopg2.connect(os.environ['DATABASE_URL'])
cur = conn.cursor()

cur.execute("SELECT * FROM blacklist")
print("BLACKLIST:", cur.fetchall())

cur.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 5")
print("LOGS:", cur.fetchall())

cur.execute("SELECT * FROM whitelist")
print("WHITELIST:", cur.fetchall())

cur.execute("SELECT username, role FROM users")
print("USERS:", cur.fetchall())

conn.close()
