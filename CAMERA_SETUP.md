# NETAD Camera Setup Guide (ngrok + webcam/RTSP)

## Requirements
- Python installed
- ngrok installed (`winget install Ngrok.Ngrok`)
- ffmpeg installed (`winget install Gyan.FFmpeg`)

---

## Every Time You Want to Use the Camera

### Step 1 — Open Terminal 1: Start the camera stream server

**If using laptop webcam:**
```powershell
cd C:\Users\ADMIN1\Downloads\files
python webcam_stream.py
```

**If using RTSP IP cam:**
```powershell
cd C:\Users\ADMIN1\Downloads\files
$env:CAMERA_SOURCE = "rtsp://DexterMorgan:Th3_84y_H4r80r_8Utch3r@192.168.68.120:554/stream1"
python webcam_stream.py
```

Wait for:
```
[NETAD] Stream ready! ✓
[NETAD] Open: http://localhost:8080
```

---

### Step 2 — Open Terminal 2 (new window): Start ngrok tunnel

```powershell
ngrok http 8080
```

Wait for:
```
Forwarding  https://xxxx.ngrok-free.app -> http://localhost:8080
```

Copy the `https://xxxx.ngrok-free.app` URL.

---

### Step 3 — Connect camera in NETAD dashboard

1. Open your Railway site and login
2. Go to **OVERVIEW** tab
3. Under **Camera Feeds → CAM 1** — paste:
   ```
   https://xxxx.ngrok-free.app/video
   ```
4. Click **📷 CONNECT**
5. Live feed should appear

---

## Important Reminders

| Rule | Why |
|------|-----|
| Keep BOTH terminals open while using camera | Closing either kills the stream |
| ngrok URL changes every restart | Update the input in dashboard after each restart |
| Laptop must stay awake | Sleep/hibernate kills the stream |
| Use ngrok URL only (not RTSP) in dashboard CAM input | RTSP can't reach Railway from local network |
| RTSP URL goes in `$env:CAMERA_SOURCE` only | Only for `webcam_stream.py` locally |

---

## If Something Goes Wrong

**"Stream ready" but black screen in dashboard:**
- Open `https://xxxx.ngrok-free.app` in browser first
- If ngrok warning page appears, click "Visit Site"
- Then try connecting in dashboard again

**Camera not opening (RTSP):**
- Test in VLC first: Media → Open Network Stream → paste RTSP URL
- If VLC works, ffmpeg should work too

**ngrok "session expired":**
- Free ngrok disconnects after ~2 hours idle
- Just restart: `ngrok http 8080` and get new URL

**Lost ngrok authtoken:**
- Login at dashboard.ngrok.com → Your Authtoken → copy
- Run: `ngrok config add-authtoken YOUR_TOKEN`

---

## Quick Reference

```
RTSP cam URL:   rtsp://DexterMorgan:Th3_84y_H4r80r_8Utch3r@192.168.68.120:554/stream1
Stream server:  http://localhost:8080
Stream path:    http://localhost:8080/video
ngrok tunnel:   ngrok http 8080
Dashboard cam:  https://xxxx.ngrok-free.app/video
```
