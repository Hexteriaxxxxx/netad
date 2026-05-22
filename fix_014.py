content = open('webcam_stream.py', encoding='utf-8').read()

old = """@app.route('/')
def index():
    return f'''
    <html><body style="background:#000;color:#0f0;font-family:monospace;padding:20px">
    <h2>NETAD Camera Stream</h2>
    <img src="/video" style="width:640px;border:2px solid #0f0"><br><br>
    <p>Source: <b>{CAMERA_SOURCE}</b></p>
    <p>Stream URL: <b>/video</b></p>
    </body></html>
    '''"""

new = """@app.route('/')
def index():
    return '''
    <html><body style="background:#000;color:#0f0;font-family:monospace;padding:20px">
    <h2>NETAD Camera Stream</h2>
    <img src="/video" style="width:640px;border:2px solid #0f0"><br><br>
    <p>Stream active</p>
    </body></html>
    '''"""

if old in content:
    content = content.replace(old, new)
    open('webcam_stream.py', 'w', encoding='utf-8').write(content)
    print('BUG-014 Fixed!')
else:
    print('Pattern not found')
