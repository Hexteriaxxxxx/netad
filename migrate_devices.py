import psycopg2, os

conn = psycopg2.connect(os.environ.get('DATABASE_URL', 'postgresql://postgres:ZUGxNBOxblwoYPVwCGQmJgBJNdWqBIBX@viaduct.proxy.rlwy.net:57649/railway'))
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS device_keys (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(50)  NOT NULL,
    device_id   VARCHAR(255) UNIQUE NOT NULL,
    public_key  TEXT NOT NULL,
    label       VARCHAR(255) DEFAULT 'Unknown Device',
    status      VARCHAR(20)  DEFAULT 'pending',
    created_at  TIMESTAMP DEFAULT NOW(),
    approved_at TIMESTAMP
);
""")
conn.commit()
conn.close()
print("device_keys table created!")
