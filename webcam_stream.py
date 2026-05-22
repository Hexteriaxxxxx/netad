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
JPEG_QUALITY  = int(os.environ.get('WEBCAM_QUALITY', 70))
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
        '-vf', 'scale=640:480', '-r', '15',
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
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
    cap.set(cv2.CAP_PROP_FPS, 15)
    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
    if not cap.isOpened():
        print(f"[NETAD] ERROR: Could not open webcam {src}")
        return
    print(f"[NETAD] Webcam {src} opened via DirectShow ✓")
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
        time.sleep(1/15)
    cap.release()

def generate_frames():
    while True:
        with _frame_lock:
            frame = _latest_frame
        if frame:
            yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
        time.sleep(1/15)

# ── BUG-014: Never expose RTSP credentials in HTML ──
@app.route('/')
def index():
    with _frame_lock:
        has_frame = _latest_frame is not None
    status = 'LIVE' if has_frame else 'WAITING FOR FRAMES...'
    return f'''
    <html><body style="background:#000;color:#0f0;font-family:monospace;padding:20px">
    <h2>NETAD Camera Stream</h2>
    <img src="/video" style="width:640px;border:2px solid #0f0"><br><br>
    <p>Status: <b>{status}</b></p>
    <p>Stream URL: <b>/video</b></p>
    </body></html>
    '''

@app.route('/video')
def video_feed():
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
    print(f"[NETAD] Quality: {JPEG_QUALITY}% | FPS: 15")

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
