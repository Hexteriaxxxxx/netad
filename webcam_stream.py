# webcam_stream.py — NETAD Laptop Webcam Server
# Streams your laptop webcam as MJPEG over HTTP
# Run this separately: python webcam_stream.py
# Then expose it with: ngrok http 8080

import cv2
from flask import Flask, Response
import threading
import time
import os

app = Flask(__name__)

PORT = int(os.environ.get('WEBCAM_PORT', 8080))
CAMERA_INDEX = int(os.environ.get('WEBCAM_INDEX', 0))  # 0 = default laptop webcam
JPEG_QUALITY = int(os.environ.get('WEBCAM_QUALITY', 70))

# ── Camera ──
_cap = None
_cap_lock = threading.Lock()

def get_cap():
    global _cap
    with _cap_lock:
        if _cap is None or not _cap.isOpened():
            _cap = cv2.VideoCapture(CAMERA_INDEX)
            _cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            _cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            _cap.set(cv2.CAP_PROP_FPS, 30)
            _cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        return _cap

def generate_frames():
    while True:
        cap = get_cap()
        ret, frame = cap.read()
        if not ret:
            time.sleep(0.1)
            continue
        ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY])
        if not ret:
            continue
        yield (
            b'--frame\r\n'
            b'Content-Type: image/jpeg\r\n\r\n' +
            buffer.tobytes() +
            b'\r\n'
        )
        time.sleep(0.033)  # ~30fps

# ── Routes ──
@app.route('/')
def index():
    return '''
    <html><body style="background:#000;color:#0f0;font-family:monospace;padding:20px">
    <h2>NETAD Webcam Stream</h2>
    <img src="/video" style="width:640px;border:2px solid #0f0"><br><br>
    <p>MJPEG URL: <b>/video</b></p>
    <p>Use this URL in NETAD: <b>http://&lt;your-ngrok-url&gt;/video</b></p>
    </body></html>
    '''

@app.route('/video')
def video_feed():
    return Response(
        generate_frames(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

@app.route('/status')
def status():
    cap = get_cap()
    return {'running': cap.isOpened(), 'port': PORT, 'camera_index': CAMERA_INDEX}

if __name__ == '__main__':
    print(f"[NETAD Webcam] Starting on http://localhost:{PORT}")
    print(f"[NETAD Webcam] Camera index: {CAMERA_INDEX}")
    print(f"[NETAD Webcam] Stream URL: http://localhost:{PORT}/video")
    print(f"[NETAD Webcam] After ngrok: set CAMERA_1_URL=https://xxxx.ngrok-free.app/video")
    app.run(host='0.0.0.0', port=PORT, threaded=True)
