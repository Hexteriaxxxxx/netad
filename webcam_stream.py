# webcam_stream.py — NETAD Camera Stream Server
# Supports: laptop webcam (index 0) OR RTSP IP cam via ffmpeg
# Run: python webcam_stream.py
# Webcam:  set CAMERA_SOURCE=0
# RTSP:    set CAMERA_SOURCE=rtsp://user:pass@IP:554/stream
# Then:    ngrok http 8080  →  paste ngrok URL into dashboard CAM input

import subprocess
import threading
import time
import os
import cv2
from flask import Flask, Response, request

app = Flask(__name__)

PORT          = int(os.environ.get('WEBCAM_PORT', 8080))
JPEG_QUALITY  = int(os.environ.get('WEBCAM_QUALITY', 40))   # lowered: 70→40, reduces frame size ~50%
CAM_WIDTH     = int(os.environ.get('WEBCAM_WIDTH', 320))    # lowered: 640→320 for Railway bandwidth
CAM_HEIGHT    = int(os.environ.get('WEBCAM_HEIGHT', 240))   # lowered: 480→240
CAM_FPS       = int(os.environ.get('WEBCAM_FPS', 8))        # lowered: 15→8 matches server serve rate
CAMERA_SOURCE = os.environ.get('CAMERA_SOURCE', '0')
ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', '*')

_latest_frame = None
_frame_lock   = threading.Lock()
_running      = True

def is_rtsp(source):
    return str(source).lower().startswith('rtsp')

# ── BUG-013: Security headers ──
@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGIN
    response.headers['ngrok-skip-browser-warning']  = 'true'
    response.headers['X-Frame-Options']              = 'DENY'
    response.headers['X-Content-Type-Options']       = 'nosniff'
    response.headers['X-XSS-Protection']             = '1; mode=block'
    response.headers['Referrer-Policy']              = 'strict-origin-when-cross-origin'
    return response

def capture_loop_ffmpeg(source):
    global _latest_frame, _running
    cmd = [
        'ffmpeg', '-rtsp_transport', 'tcp', '-i', source,
        '-vf', f'scale={CAM_WIDTH}:{CAM_HEIGHT}', '-r', str(CAM_FPS),
        '-f', 'image2pipe', '-vcodec', 'mjpeg', '-q:v', '5', 'pipe:1'
    ]
    print("[NETAD] Starting ffmpeg RTSP relay...")
    while _running:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=10**8)
            buf = b''
            while _running:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    print("[NETAD] ffmpeg stream ended, retrying...")
                    break
                buf += chunk
                start = buf.find(b'\xff\xd8')
                end   = buf.find(b'\xff\xd9')
                if start != -1 and end != -1 and end > start:
                    jpg = buf[start:end+2]
                    buf = buf[end+2:]
                    with _frame_lock:
                        _latest_frame = jpg
            proc.kill()
        except FileNotFoundError:
            print("[NETAD] ERROR: ffmpeg not found!")
            print("[NETAD] Install: winget install Gyan.FFmpeg")
            break
        except Exception as e:
            print(f"[NETAD] ffmpeg error: {e}")
        time.sleep(2)

def capture_loop_opencv(source):
    global _latest_frame, _running
    try:
        src = int(source)
    except ValueError:
        src = source
    cap = cv2.VideoCapture(src, cv2.CAP_DSHOW)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, CAM_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, CAM_HEIGHT)
    cap.set(cv2.CAP_PROP_FPS, CAM_FPS)
    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
    if not cap.isOpened():
        print(f"[NETAD] ERROR: Could not open webcam {src}")
        return
    print(f"[NETAD] Webcam {src} @ {CAM_WIDTH}x{CAM_HEIGHT} {CAM_FPS}fps q{JPEG_QUALITY}")
    while _running:
        ret, frame = cap.read()
        if not ret:
            print("[NETAD] Frame grab failed, retrying...")
            cap.release(); time.sleep(1)
            cap = cv2.VideoCapture(src, cv2.CAP_DSHOW)
            continue
        ret2, buf = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY])
        if ret2:
            with _frame_lock:
                _latest_frame = buf.tobytes()
        time.sleep(1/CAM_FPS)
    cap.release()

import base64

def generate_frames():
    """MJPEG generator — kept for backward compat but NOT used by dashboard anymore."""
    while True:
        with _frame_lock:
            frame = _latest_frame
        if frame:
            yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
        time.sleep(1/CAM_FPS)

# ── BUG-014: Never expose RTSP credentials in HTML ──
@app.route('/')
def index():
    with _frame_lock:
        has_frame = _latest_frame is not None
    status = 'LIVE' if has_frame else 'WAITING FOR FRAMES...'
    return f'''
    <html><body style="background:#000;color:#0f0;font-family:monospace;padding:20px">
    <h2>NETAD Camera Stream</h2>
    <p>Status: <b>{status}</b></p>
    <p>Frame endpoint: <b>/frame</b> (JSON, used by dashboard)</p>
    <p>MJPEG endpoint: <b>/video</b> (legacy)</p>
    </body></html>
    '''

@app.route('/frame')
def frame_json():
    """Returns the latest frame as base64 JSON.
    Dashboard polls this every ~150ms via short fetch — no persistent connection.
    This is the fix for the 'MJPEG blocks AI chat' bug:
      Old: img.src = persistent MJPEG stream = 1 permanent HTTP connection per browser
      New: JS fetch('/frame') every 150ms = short-lived requests, never blocks other APIs
    """
    with _frame_lock:
        frame = _latest_frame
    if not frame:
        return {'ok': False, 'frame': None}, 503
    b64 = base64.b64encode(frame).decode('utf-8')
    return {'ok': True, 'frame': b64, 'ts': time.time()}

@app.route('/stream')
def stream_redirect():
    """Alias — so both /stream and /video work."""
    return video_feed()

@app.route('/video')
def video_feed():
    """Legacy MJPEG endpoint — still works for direct browser testing.
    DO NOT use in dashboard — blocks AI chat due to persistent connection."""
    return Response(
        generate_frames(),
        mimetype='multipart/x-mixed-replace; boundary=frame',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/status')
def status_route():
    with _frame_lock:
        has_frame = _latest_frame is not None
    return {'running': has_frame, 'port': PORT}

if __name__ == '__main__':
    print(f"[NETAD] Starting on http://localhost:{PORT}")
    print(f"[NETAD] Quality: {JPEG_QUALITY}% | FPS: {CAM_FPS} | Res: {CAM_WIDTH}x{CAM_HEIGHT}")

    if is_rtsp(CAMERA_SOURCE):
        print("[NETAD] Mode: RTSP via ffmpeg")
        t = threading.Thread(target=capture_loop_ffmpeg, args=(CAMERA_SOURCE,), daemon=True)
    else:
        src = CAMERA_SOURCE if CAMERA_SOURCE else '0'
        print(f"[NETAD] Mode: Webcam index {src} via OpenCV DirectShow")
        t = threading.Thread(target=capture_loop_opencv, args=(src,), daemon=True)

    t.start()

    print("[NETAD] Waiting for first frame...")
    for _ in range(40):
        with _frame_lock:
            if _latest_frame: break
        time.sleep(0.5)

    if _latest_frame:
        print("[NETAD] Stream ready! ✓")
    else:
        print("[NETAD] WARNING: No frames yet — check camera source")

    print(f"[NETAD] Open: http://localhost:{PORT}")
    app.run(host='0.0.0.0', port=PORT, threaded=True)
