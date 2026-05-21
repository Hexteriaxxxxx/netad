import os, sys
from dotenv import load_dotenv
load_dotenv()

print("=== NETAD ENV CHECK ===")
for key in ['SECRET_KEY', 'DATABASE_URL', 'ALLOWED_ORIGIN', 'GROQ_API_KEY']:
    val = os.environ.get(key, '')
    print(f"{key}: {'SET (' + str(len(val)) + ' chars)' if val else 'MISSING'}")
print("=== END ===")

sk = os.environ.get('SECRET_KEY', '')
if not sk:
    print("FATAL: SECRET_KEY is missing or empty")
    sys.exit(1)

# Continue with rest of main.py
exec(open('main_app.py').read())
