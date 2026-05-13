import psycopg2, os

conn = psycopg2.connect(os.environ.get('DATABASE_URL', 'postgresql://postgres:ZUGxNBOxblwoYPVwCGQmJgBJNdWqBIBX@viaduct.proxy.rlwy.net:57649/railway'))
cur = conn.cursor()
cur.execute("ALTER TABLE chat_logs ADD COLUMN IF NOT EXISTS sender VARCHAR(50) DEFAULT '';")
conn.commit()
conn.close()
print("Migration done: sender column added to chat_logs!")
