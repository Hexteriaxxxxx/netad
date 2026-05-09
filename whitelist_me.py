import urllib.request, psycopg2

my_ip = urllib.request.urlopen('https://api.ipify.org').read().decode()
conn = psycopg2.connect('postgresql://postgres:ZUGxNBOxblwoYPVwCGQmJgBJNdWqBIBX@viaduct.proxy.rlwy.net:57649/railway')
cur = conn.cursor()
cur.execute("INSERT INTO whitelist (ip, label) VALUES (%s, %s) ON CONFLICT (ip) DO NOTHING", (my_ip, 'My device'))
conn.commit()
conn.close()
print(f'Whitelisted: {my_ip}')