content = open('templates/dashboard.html', encoding='utf-8').read()

old = "  // Also register on server side for Guard AI awareness\n  fetch('/api/camera/connect', {\n    method: 'POST',\n    headers: {'Content-Type': 'application/json'},\n    body: JSON.stringify({cam_id: camId, url: url})\n  }).catch(()=>{});"

new = "  // Only register HTTP/ngrok URLs on server - RTSP cant be reached from Railway\n  if (url.toLowerCase().startsWith('http')) {\n    fetch('/api/camera/connect', {\n      method: 'POST',\n      headers: {'Content-Type': 'application/json'},\n      body: JSON.stringify({cam_id: camId, url: url})\n    }).catch(()=>{});\n  }"

if old in content:
    content = content.replace(old, new)
    open('templates/dashboard.html', 'w', encoding='utf-8').write(content)
    print('Patched!')
else:
    print('Pattern not found')
