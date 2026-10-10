Aegis Vault | Stateless Secure File Cryptography Engine

Aegis Vault is an advanced, production-grade secure file cryptography and decentralized storage gateway built using Python Flask, the cryptography library (PBKDF2HMAC & Fernet), and IPFS integration. Designed for maximum security and zero-footprint execution, it ensures that your sensitive files reside only in transient memory buffers.

🚀 Key Features

Military-Grade Cryptography: Leverages PBKDF2HMAC with SHA-256 (set at 480,000 iterations) for robust key derivation, coupled with Fernet (AES-128 in CBC mode with HMAC authentication) for authenticated encryption.

Stateless RAM Operations: All file encryption and decryption processes occur entirely in transient memory using io.BytesIO streams, leaving zero plaintext footprint on disk. Manual RAM purging triggers Python's garbage collector (gc.collect()).

Decentralized IPFS Broadcast & Auto-Burn: Securely pins encrypted payloads to IPFS (via Pinata) with optional auto-burn/unpin functionality upon retrieval.

Real-Time Telemetry & Security Auditing: Live background thread polling monitors CPU and RAM load, while an automated log capture stream allows instant downloading of system security audit logs.

Rate-Limiting & Security Headers: Integrated rate limiting via Flask-Limiter protects endpoints against brute-force and DDoS attacks.

🛠️ Tech Stack

Backend: Python, Flask, Gunicorn, APScheduler, Cryptography, Psutil, Requests, Flask-Limiter.

Frontend: HTML5, Bootstrap 5, Tailwind-inspired Glassmorphism CSS, Vanilla JavaScript, FontAwesome.

Deployment: Render (Backend/Full-Stack Service).

📂 Project Structure

Aegis_Vault/
├── app.py                     # Main Flask application & crypto engine backend
├── requirements.txt           # Python package dependencies
├── README.md                  # Project documentation
└── templates/
    ├── index.html             # Operational Terminal UI (Dashboard)
    └── main_landing_page.html # Landing Page UI


⚙️ Local Development Setup

Clone the repository:

git clone https://github.com/gagandeepg2007-create/Aegis_Vault.git
cd Aegis_Vault


Create and activate a virtual environment:

python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate


Install dependencies:

pip install -r requirements.txt


Run the Flask application:

python app.py


Open your browser and navigate to http://localhost:5000.

🌐 Production Deployment (Render)

Connect your GitHub repository (Aegis_Vault) to Render.

Create a new Web Service with the following settings:

Runtime: Python 3

Build Command: pip install -r requirements.txt

Start Command: gunicorn app:app

Configure environment variables (optional):

PINATA_JWT: Your Pinata API token for IPFS cloud broadcasting.

PINATA_GATEWAY: Custom IPFS gateway URL (defaults to https://gateway.pinata.cloud/ipfs/).

🔒 Security Best Practices

Master Passwords: Always use strong, high-entropy passphrases. Keys are derived dynamically using unique 16-byte cryptographically secure salts (os.urandom()) prepended to each encrypted .aegis file package.

Transient Memory: Files are automatically dropped from RAM buffers immediately after client transmission.