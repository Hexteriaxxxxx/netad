import re

content = open('templates/dashboard.html', encoding='utf-8').read()

# 1. Remove duplicate floating Camera URLs panel (cam1-url-mgr)
idx = content.find('cam1-url-mgr')
if idx != -1:
    open_div = content.rfind('<div', 0, idx)
    depth = 0
    i = open_div
    while i < len(content):
        if content[i:i+4] == '<div':
            depth += 1
        elif content[i:i+6] == '</div>':
            depth -= 1
            if depth == 0:
                content = content[:open_div] + content[i+6:]
                print('Removed duplicate Camera URLs panel')
                break
        i += 1
else:
    print('cam1-url-mgr not found - already removed')

# 2. Fix button onclick calls in HTML
content = content.replace('onclick="connectCamDirect(1)"', 'onclick="connectCam(1)"')
content = content.replace('onclick="connectCamDirect(2)"', 'onclick="connectCam(2)"')
content = content.replace('onclick="disconnectCamDirect(1)"', 'onclick="disconnectCam(1)"')
content = content.replace('onclick="disconnectCamDirect(2)"', 'onclick="disconnectCam(2)"')
print('Fixed button onclick calls')

# 3. Fix connectCamDirect function - remove error loop, no cache-busting timestamp
# Find and replace the function
start = content.find('function connectCamDirect(camId)')
if start == -1:
    start = content.find('function connectCam(camId)')
    
if start != -1:
    # Find end of function by counting braces
    depth = 0
    i = start
    func_start = start
    in_func = False
    while i < len(content):
        if content[i] == '{':
            depth += 1
            in_func = True
        elif content[i] == '}':
            depth -= 1
            if in_func and depth == 0:
                func_end = i + 1
                break
        i += 1
    
    new_func = """function connectCam(camId) {
  const input = document.getElementById('cam' + camId + '-url-input');
  const url = input ? input.value.trim() : '';
  if (!url) { showToast('Paste a camera URL first', 'error'); return; }
  const img = document.getElementById('cam' + camId + '-img');
  const isHttp = url.toLowerCase().startsWith('http');
  img.onerror = null;
  img.onload = null;
  // HTTP: load directly in browser (no relay, no timestamp = no reload loop)
  // RTSP: use server relay
  img.src = isHttp ? url : '/api/camera/' + camId + '/stream';
  let errCount = 0;
  img.onerror = function() {
    errCount++;
    if (errCount >= 3) {
      showToast('Cam ' + camId + ': stream failed — check URL', 'error', 5000);
      disconnectCam(camId);
    }
  };
  img.onload = function() { errCount = 0; };
  document.getElementById('cam' + camId + '-locked').style.display = 'none';
  document.getElementById('cam' + camId + '-live').style.display = 'block';
  document.getElementById('cam' + camId + '-disconnect').style.display = 'inline-block';
  document.getElementById('cam-badge').textContent = 'LIVE';
  showToast('Cam ' + camId + ' connected', 'success');
  fetch('/api/camera/connect', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({cam_id: camId, url: url})
  }).catch(function(){});
}
function connectCamDirect(camId) { connectCam(camId); }"""

    content = content[:func_start] + new_func + content[func_end:]
    print('Patched connectCam function')
else:
    print('connectCam/connectCamDirect not found')

# 4. Fix disconnectCamDirect -> disconnectCam
content = content.replace('function disconnectCamDirect(camId)', 'function disconnectCam(camId)')
# Also replace _directCamUrls references
content = content.replace("_directCamUrls[camId] = ''", "_camUrls[camId] = ''")
content = content.replace("_directCamUrls[camId] = url", "_camUrls[camId] = url")
content = content.replace("const _directCamUrls = {1:'',2:''}", "const _camUrls = {1:'',2:''}")
content = content.replace("Object.values(_directCamUrls)", "Object.values(_camUrls)")
print('Fixed disconnect and _camUrls references')

open('templates/dashboard.html', 'w', encoding='utf-8').write(content)
print('Done!')
