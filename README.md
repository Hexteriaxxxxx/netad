# NETAD — Network Enhanced Threat and Anomaly Detection
> Physical CCTV Network Monitoring System with Multi-Layer Security
> COMP 012 – Network Administration | PUP Santa Rosa | AY 2025-2026

## 🌐 Live Demo
**URL:** https://web-production-c5a76.up.railway.app

---

## 👥 Team
| Name | Role |
|------|------|
| Gian (admin) | Project Manager |
| Kevin | Lead Developer |
| Josiah | Co-Lead Developer |
| JM | Node Developer A |
| Karl | Security Designer |
| Nico | Multi-role |
| LJ | Node Developer B |

---

## 📋 Project Overview
NETAD is a web-based CCTV monitoring system secured by a **6-layer consensus authentication** mechanism. All 6 security nodes must pass simultaneously before a user is granted access to the live camera feed.

### Security Layers (All 6 must PASS)
| Node | Name | Description |
|------|------|-------------|
| 1 | Password Verification | bcrypt cost-12 hash against PostgreSQL |
| 2 | Request Timestamp | Login form must be submitted within 30 seconds |
| 3 | IP Whitelist | Client IP must be pre-approved |
| 4 | Device Signature | ECDSA P-256 — private key never leaves the browser |
| 5 | Session Token | One-time token, atomic claim (replay-proof) |
| 6 | Rate Limiting | Max 5 failed attempts/hour, auto-blacklist 30 min |

### AI Layer
- **Isolation Forest** anomaly detection — runs before the 6 nodes
- Detects suspicious login patterns (off-hours, burst attempts, unknown IPs)
- **Guard AI** — Groq LLaMA 3.3-70B with real-time threat analysis and tool execution

---

## 🏗️ Physical Network Setup
```
[IP Camera / Laptop Webcam]
         |
    [Router/Switch]
         |
   [Laptop (ngrok)]
         |
   [ngrok tunnel]
         |
  [Railway Cloud Server]
         |
   [Browser Dashboard]
```

- IP Camera connected to router via RJ-45 or WiFi
- `webcam_stream.py` runs locally — converts RTSP/webcam to HTTP/MJPEG
- ngrok exposes local stream to internet
- Dashboard connects directly to ngrok URL (browser → ngrok → camera)

---

## 🛠️ Tech Stack
| Component | Technology |
|-----------|-----------|
| Backend | Flask + Flask-SocketIO (eventlet) |
| Database | PostgreSQL (Railway) |
| Authentication | bcrypt + ECDSA P-256 (WebCrypto API) |
| AI/ML | scikit-learn Isolation Forest |
| Guard AI | Groq API (LLaMA 3.3-70B) |
| Camera | OpenCV, RTSP/HTTP MJPEG |
| Deployment | Railway (cloud) |
| Real-time | Socket.IO |

---

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.10+
- PostgreSQL (or Railway PostgreSQL)
- ngrok account (free)
- ffmpeg (for RTSP cameras)

### 1. Clone the repository
```bash
git clone https://github.com/Hexteriaxxxxx/netad.git
cd netad
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Set up environment variables
Create a `.env` file in the project root:
```env
DATABASE_URL=postgresql://user:password@host:port/railway
SECRET_KEY=your_secret_key_here
GROQ_API_KEY=your_groq_api_key
ALLOWED_ORIGIN=http://localhost:5000
RSA_PRIVATE_KEY_B64=your_rsa_private_key_base64
RSA_PUBLIC_KEY_B64=your_rsa_public_key_base64
EMERGENCY_PATH=your_emergency_path
EMERGENCY_PASSWORD=your_emergency_password
HOST=0.0.0.0
PORT=5000
```

### 4. Set up database
Run in PgAdmin or psql:
```bash
psql $DATABASE_URL -f setup_database.sql
```

### 5. Seed users
```bash
python security/generate_keys.py
```

### 6. Run the application
```bash
python main.py
```

### 7. Set up camera (ngrok)
**Terminal 1 — Start camera stream:**
```cmd
set CAMERA_SOURCE=0
python webcam_stream.py
```

**Terminal 2 — Expose via ngrok:**
```cmd
ngrok http 8080
```

Paste the ngrok URL into the dashboard CAM 1 input field.

---

## 📁 Project Structure
```
netad/
├── main.py                  # Main Flask application + all 6 security nodes
├── database.py              # PostgreSQL database manager
├── webcam_stream.py         # Local camera stream server (ngrok relay)
├── block.py                 # Blockchain-inspired request signing
├── consensus.py             # Legacy (archived)
├── setup_database.sql       # Database schema
├── requirements.txt         # Python dependencies
├── Procfile                 # Railway deployment config
├── railway.toml             # Railway build config
├── ai/
│   └── anomaly.py           # Isolation Forest anomaly detection
├── security/
│   ├── signer.py            # RSA-PSS request signing
│   └── generate_keys.py     # Key generation + user seeding
├── templates/
│   ├── login.html           # Login page with ECDSA device registration
│   └── dashboard.html       # Security monitoring dashboard
└── nodes/                   # Legacy node files (archived)
```

---

## 🗄️ Database Schema
- `users` — team member accounts with bcrypt-hashed passwords
- `whitelist` — approved IP addresses per user
- `blacklist` — temporarily or permanently blocked IPs
- `logs` — all login attempts with IP, result, timestamp
- `sessions` — active user sessions with heartbeat tracking
- `used_tokens` — one-time session tokens (replay attack prevention)
- `ai_logs` — Isolation Forest anomaly detection results
- `chat_logs` — Guard AI conversation history
- `device_keys` — ECDSA P-256 public keys per device per user

---

## 🔐 Security Features
- ✅ bcrypt cost-12 password hashing
- ✅ ECDSA P-256 device signature (private key never leaves browser)
- ✅ One-time session tokens (atomic claim, replay-proof)
- ✅ IP whitelist enforcement
- ✅ Rate limiting with auto-blacklist
- ✅ CSRF token validation (5-minute expiry, single-use)
- ✅ Request timestamp validation (30-second window)
- ✅ RSA-PSS server-side request signing
- ✅ AI anomaly detection (Isolation Forest)
- ✅ Real-time threat detection (SQL injection, brute force, replay attacks)
- ✅ Guard AI with tool execution (block IP, kick session, whitelist management)

---

## ☁️ Cloud Deployment (Railway)
1. Push to GitHub — Railway auto-deploys from `main` branch
2. Add PostgreSQL service in Railway dashboard
3. Set all environment variables in Railway → Variables tab
4. Set `DATABASE_URL=${{Postgres.DATABASE_URL}}` for auto-connection

---

## 📸 Screenshots
*(Add screenshots of: physical setup, login page, dashboard, camera feed, logs)*

---

## 📊 Network Diagram
```
[IP CAMERA] ──── [ROUTER] ──── [LAPTOP]
                                  │
                            webcam_stream.py
                                  │
                              [ngrok]
                                  │
                          [Railway Cloud]
                                  │
                          [Web Dashboard]
                          (Browser Client)
```
