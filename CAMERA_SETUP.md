# NETAD — Camera Setup Guide (ngrok + Webcam / RTSP)

## One-time Setup

### 1. Install ngrok
```powershell
winget install Ngrok.Ngrok
```

### 2. Get authtoken
- Pumunta sa [dashboard.ngrok.com](https://dashboard.ngrok.com) → login/signup
- Your Authtoken → copy
```cmd
ngrok config add-authtoken YOUR_TOKEN_HERE
```

---

## Everyngrok http 8080 Session (gawin bawat demo/use)

### Terminal 1 — Start webcam stream

**Laptop webcam:**
```cmd
cd C:\Users\ADMIN1\Downloads\files
set CAMERA_SOURCE=0
python webcam_stream.py
```

**RTSP IP cam:**
```cmd
cd C:\Users\ADMIN1\Downloads\files
set CAMERA_SOURCE=rtsp://USERNAME:PASSWORD@CAMERA_IP:554/stream1
python webcam_stream.py
```

Hintayin:
```
[NETAD] Webcam 0 opened via DirectShow ✓
[NETAD] Stream ready! ✓
[NETAD] Open: http://localhost:8080
```

### Terminal 2 — Start ngrok tunnel (bagong window)
```cmd

```

Hintayin:
```
Forwarding  https://xxxx.ngrok-free.app -> http://localhost:8080
```
Copy yung `https://xxxx.ngrok-free.app` URL.

---

## Sa NETAD Dashboard

1. Mag-login sa Railway site
2. Pagkatapos ng **GRANTED** → nasa dashboard ka na
3. **OVERVIEW tab → Camera Feeds → CAM 1 input** → i-paste:
```
https://xxxx.ngrok-free.app/video
```
4. Click **📷 CONNECT**
5. Live feed dapat lumabas

> **Note:** RTSP URLs ay gumagana din sa CAM input — Railway server ang mag-re-relay nito.

---

## Reminders

| | |
|---|---|
| Parehong terminals dapat bukas | Pag isang naisara, mawawala ang stream |
| ngrok URL nagbabago pag nirestart | I-update sa dashboard input bawat session |
| Gamitin CMD hindi PowerShell | `set CAMERA_SOURCE=0` ay CMD syntax |
| Laptop dapat gising | Sleep mode = dead stream |
| HTTP/ngrok at RTSP — parehong gumagana | Railway server ang nag-fe-fetch, hindi browser |

---

## Troubleshooting

**Black screen sa dashboard:**
- I-check kung tumatakbo pa ang `webcam_stream.py` at `ngrok` sa terminals
- I-click **✕ DISC** → i-paste ulit yung URL → **📷 CONNECT**
- Hindi na kailangan i-visit ang ngrok URL sa browser — awtomatiko na itong na-bypass ng server

**"No frames yet" error:**
- May ibang app (Teams, Zoom, etc.) na nag-o-occupy ng camera
- Isara yung ibang apps → ulitin ang `python webcam_stream.py`

**ngrok "ERR_NGROK_3200" o session expired:**
- Libre ngrok ≈ 2 hours session
- Restart: `ngrok http 8080` → bagong URL → i-update sa dashboard

**RTSP hindi gumagana:**
- I-test muna sa VLC: Media → Open Network Stream → i-paste ang RTSP URL
- Kung gumagana sa VLC → gumagana din sa NETAD

---

## Quick Copy-Paste

```cmd
cd C:\Users\ADMIN1\Downloads\files
set CAMERA_SOURCE=0
python webcam_stream.py
```
```cmd
ngrok http 8080
```


# NETAD — Camera Setup Guide IP CAM WIRED

## Ano ang kailangan
- Laptop ni Josiah (may Tapo C310 na nakaconnect sa router)
- Cloudflared installed
- `webcam_stream.py` nasa `C:\Users\jusaya\Downloads\netad`

---

## One-time Setup — I-install ang Cloudflared

I-download ang cloudflared: [https://github.com/cloudflare/cloudflared/releases/latest](https://github.com/cloudflare/cloudflared/releases/latest)

I-download ang `cloudflared-windows-amd64.exe` → i-rename sa `cloudflared.exe` → ilagay sa `C:\Windows\System32` para accessible sa kahit saang terminal.

---

## Bawat Session (gawin bawat demo/use)

### Terminal 1 — I-start ang webcam stream

```cmd
cd C:\Users\jusaya\Downloads\netad
set CAMERA_SOURCE=rtsp://username:password@192.168.93.16:554/stream2
python webcam_stream.py
```

> Palitan ang `username` at `password` ng actual Tapo credentials mo sa Tapo app.

Hintayin ito:
```
[NETAD] Stream ready! ✓
[NETAD] Open: http://localhost:8080
```

### Terminal 2 — I-start ang Cloudflare tunnel (bagong window)

```cmd
cloudflared tunnel --url http://localhost:8080
```

Hintayin ito at kopyahin ang URL:
```
https://xxxx-xxxx.trycloudflare.com
```

---

## Sa NETAD Dashboard

1. Pumunta sa `https://web-production-c5a76.up.railway.app`
2. Mag-login
3. **Overview tab → Camera Feeds → CAM 1 input** → i-paste:
```
https://xxxx-xxxx.trycloudflare.com
```
4. Click **📷 CONNECT**
5. Dapat lumabas ang live feed ng Tapo C310

> Automatic na ginagamit ng dashboard ang `/frame` endpoint — hindi na kailangan idagdag manually.

---

## Reminders

| | |
|---|---|
| Parehong terminals bukas | Pag isang naisara, mawawala ang stream |
| Cloudflare URL nagbabago pag nirestart | I-update sa dashboard bawat session |
| Laptop ni Josiah dapat gising | Sleep mode = dead stream |
| Router at Tapo C310 dapat naka-on | Walang camera = walang feed |
| Other users — hindi na kailangan mag-paste | Auto-connect na sila kapag naka-connect si Josiah |

---

## Troubleshooting

**Blank/black screen sa dashboard:**
- I-check kung tumatakbo pa ang dalawang terminals
- Click **✕ DISC** → i-paste ulit ang URL → **📷 CONNECT**

**"Lost feed" toast sa dashboard:**
- Baka natulog ang laptop o nasara ang terminal
- I-restart ang `webcam_stream.py` at `cloudflared` → bagong URL → i-connect ulit

**Tapo C310 hindi nag-a-appear:**
- I-test muna sa VLC: Media → Open Network Stream → i-paste ang RTSP URL
- Kung gumagana sa VLC → gumagana din sa NETAD

**Nagbabago ang IP ng Tapo C310:**
- I-set ng static IP sa Tapo app: Settings → Network → i-set ng fixed IP

---

## Quick Reference

**RTSP URL ng Tapo C310:**
```
rtsp://username:password@192.168.93.16:554/stream2
```

**Terminal 1:**
```cmd
cd C:\Users\jusaya\Downloads\netad
set CAMERA_SOURCE=rtsp://username:password@192.168.93.16:554/stream2
python webcam_stream.py
```

**Terminal 2:**
```cmd
cloudflared tunnel --url http://localhost:8080
```
