import os
import urllib.request
import psycopg2
from dotenv import load_dotenv
load_dotenv()

my_ip = urllib.request.urlopen('https://api.ipify.org').read().decode()
conn = psycopg2.connect(os.environ['DATABASE_URL'])
cur = conn.cursor()
cur.execute(
    "INSERT INTO whitelist (ip, label) VALUES (%s, %s) ON CONFLICT (ip) DO NOTHING",
    (my_ip, 'My device')
)
conn.commit()
conn.close()
print(f'Whitelisted: {my_ip}')
