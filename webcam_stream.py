# webcam_stream.py — NETAD Laptop Webcam Server (Windows-optimized)
# Run: python webcam_stream.py
# Then: ngrok http 8080

import cv2
from flask import Flask, Response
import threading
import time
import os

app = Flask(__name__)

PORT = int(os.environ.get('WEBCAM_PORT', 8080))
JPEG_QUALITY = int(os.environ.get('WEBCAM_QUALITY', 50))

_latest_frame = None
_frame_lock = threading.Lock()
_running = True

def open_camera():
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
    cap.set(cv2.CAP_PROP_FPS, 15)
    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
    return cap

def capture_loop():
    global _latest_frame, _running
    cap = open_camera()
    if not cap.isOpened():
        print("[NETAD Webcam] ERROR: Could not open camera!")
        return
    print("[NETAD Webcam] Camera opened via DirectShow ✓")
    while _running:
        ret, frame = cap.read()
        if not ret:
            print("[NETAD Webcam] Frame grab failed, retrying...")
            cap.release()
            time.sleep(1)
            cap = open_camera()
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

# ── CORS + ngrok bypass headers ──
@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['ngrok-skip-browser-warning'] = 'true'
    return response

@app.route('/')
def index():
    return '''
    <html><body style="background:#000;color:#0f0;font-family:monospace;padding:20px">
    <h2>NETAD Webcam Stream</h2>
    <img src="/video" style="width:640px;border:2px solid #0f0"><br><br>
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
    return {'running': has_frame, 'port': PORT}

if __name__ == '__main__':
    print(f"[NETAD Webcam] Starting on http://localhost:{PORT}")
    print(f"[NETAD Webcam] Using DirectShow (Windows-stable)")
    print(f"[NETAD Webcam] Quality: {JPEG_QUALITY}% | FPS: 15")

    t = threading.Thread(target=capture_loop, daemon=True)
    t.start()

    print("[NETAD Webcam] Waiting for first frame...")
    for _ in range(30):
        with _frame_lock:
            if _latest_frame:
                break
        time.sleep(0.2)
    print("[NETAD Webcam] Stream ready!")
    print(f"[NETAD Webcam] Open: http://localhost:{PORT}")

    app.run(host='0.0.0.0', port=PORT, threaded=True)
