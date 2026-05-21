content = open('templates/dashboard.html', encoding='utf-8').read()

# Find the function and replace it entirely
start = content.find('async function checkCameraStatus()')
if start == -1:
    print('Function not found'); exit()

# Find end by counting braces
depth = 0
i = start
func_end = start
for i in range(start, len(content)):
    if content[i] == '{': depth += 1
    elif content[i] == '}':
        depth -= 1
        if depth == 0:
            func_end = i + 1
            break

# Also remove the checkCameraStatus(); call right after
after = content[func_end:func_end+30]
if 'checkCameraStatus()' in after:
    func_end = content.find('\n', func_end + 1) + 1

old_func = content[start:func_end]
print('Replacing:', repr(old_func[:80]))

new_func = """async function checkCameraStatus(){
  try{
    const d=await fetch('/api/camera/status').then(r=>r.json());
    if(d.accessible){
      document.getElementById('cam-badge').textContent='UNLOCKED';
      for(const[k,v] of Object.entries(d.cameras||{})){
        const id=parseInt(k);
        if(v.configured&&!_camUrls[id]){
          const img=document.getElementById('cam'+id+'-img');
          img.onerror=null;
          img.src='/api/camera/'+id+'/stream';
          document.getElementById('cam'+id+'-locked').style.display='none';
          document.getElementById('cam'+id+'-live').style.display='block';
          document.getElementById('cam'+id+'-disconnect').style.display='inline-block';
          document.getElementById('cam-badge').textContent='LIVE';
        }
      }
    }
  }catch(e){}
}
checkCameraStatus();
setInterval(checkCameraStatus,5000);
"""

content = content[:start] + new_func + content[func_end:]
open('templates/dashboard.html', 'w', encoding='utf-8').write(content)
print('Patched!')
