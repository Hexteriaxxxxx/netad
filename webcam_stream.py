# webcam_stream.py — NETAD Camera Stream Server (ffmpeg-based RTSP relay)
# Supports: laptop webcam (index) OR RTSP IP cam
# Run: python webcam_stream.py
# Then: ngrok http 8080

import subprocess
import threading
import time
import os
import cv2
from flask import Flask, Response

app = Flask(__name__)

PORT         = int(os.environ.get('WEBCAM_PORT', 8080))
JPEG_QUALITY = int(os.environ.get('WEBCAM_QUALITY', 70))
CAMERA_SOURCE = os.environ.get('CAMERA_SOURCE', 'rtsp://DexterMorgan:Th3_84y_H4r80r_8Utch3r@192.168.68.120:554/stream1')

_latest_frame = None
_frame_lock   = threading.Lock()
_running      = True

def is_rtsp(source):
    return str(source).lower().startswith('rtsp')

def capture_loop_ffmpeg(source):
    """Use ffmpeg subprocess to grab RTSP frames — works even without OpenCV RTSP support."""
    global _latest_frame, _running
    cmd = [
        'ffmpeg',
        '-rtsp_transport', 'tcp',
        '-i', source,
        '-vf', 'scale=640:480',
        '-r', '15',
        '-f', 'image2pipe',
        '-vcodec', 'mjpeg',
        '-q:v', '5',
        'pipe:1'
    ]
    print(f"[NETAD] Starting ffmpeg RTSP relay...")
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
            print("[NETAD] ERROR: ffmpeg not found! Install ffmpeg and add to PATH.")
            print("[NETAD] Download: https://github.com/BtbN/FFmpeg-Builds/releases")
            break
        except Exception as e:
            print(f"[NETAD] ffmpeg error: {e}")
        time.sleep(2)

def capture_loop_opencv(source):
    """Use OpenCV for webcam index (0, 1, etc.)"""
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
            yield (
                b'--frame\r\n'
                b'Content-Type: image/jpeg\r\n\r\n' +
                frame +
                b'\r\n'
            )
        time.sleep(1/15)

@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['ngrok-skip-browser-warning'] = 'true'
    return response

@app.route('/')
def index():
    return f'''
    <html><body style="background:#000;color:#0f0;font-family:monospace;padding:20px">
    <h2>NETAD Camera Stream</h2>
    <img src="/video" style="width:640px;border:2px solid #0f0"><br><br>
    <p>Source: <b>{CAMERA_SOURCE}</b></p>
    <p>Stream URL: <b>/video</b></p>
    </body></html>
    '''

@app.route('/video')
def video_feed():
    return Response(
        generate_frames(),
        mimetype='multipart/x-mixed-replace; boundary=frame',
        headers={
            'Access-Control-Allow-Origin': '*',
            'ngrok-skip-browser-warning': 'true',
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/status')
def status():
    with _frame_lock:
        has_frame = _latest_frame is not None
    return {'running': has_frame, 'source': CAMERA_SOURCE, 'port': PORT}

if __name__ == '__main__':
    print(f"[NETAD] Starting on http://localhost:{PORT}")
    print(f"[NETAD] Camera source: {CAMERA_SOURCE}")

    if is_rtsp(CAMERA_SOURCE):
        print(f"[NETAD] Mode: RTSP via ffmpeg")
        t = threading.Thread(target=capture_loop_ffmpeg, args=(CAMERA_SOURCE,), daemon=True)
    else:
        print(f"[NETAD] Mode: Webcam via OpenCV DirectShow")
        t = threading.Thread(target=capture_loop_opencv, args=(CAMERA_SOURCE,), daemon=True)

    t.start()

    print("[NETAD] Waiting for first frame...")
    for _ in range(40):
        with _frame_lock:
            if _latest_frame: break
        time.sleep(0.5)

    if _latest_frame:
        print("[NETAD] Stream ready! ✓")
    else:
        print("[NETAD] WARNING: No frames yet — check camera or ffmpeg")

    print(f"[NETAD] Open: http://localhost:{PORT}")
    app.run(host='0.0.0.0', port=PORT, threaded=True)
