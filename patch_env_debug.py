content = open('main.py', encoding='utf-8').read()

old = """app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is not set in .env")"""

new = """# Debug — print all env vars on startup
import sys
print("=== NETAD ENV DEBUG ===")
for k in ['SECRET_KEY','DATABASE_URL','ALLOWED_ORIGIN','GROQ_API_KEY','PORT','HOST']:
    v = os.environ.get(k,'')
    print(f"  {k}: {'SET (' + str(len(v)) + ' chars)' if v else 'MISSING'}")
print("=== END DEBUG ===")

app.secret_key = os.environ.get('SECRET_KEY') or 'fallback_dev_key_change_in_prod'
if not os.environ.get('SECRET_KEY'):
    print("WARNING: SECRET_KEY not set — using fallback!")"""

if old in content:
    content = content.replace(old, new)
    open('main.py', 'w', encoding='utf-8').write(content)
    print('Patched! SECRET_KEY crash removed, debug added.')
else:
    print('Pattern not found')
