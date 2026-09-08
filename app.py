import os
import time
import psutil
import threading
import logging
import requests
import io
import gc 
import re 
from flask import Flask, render_template, request, send_file, jsonify, flash, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from io import BytesIO
from apscheduler.schedulers.background import BackgroundScheduler

# Import the OOP Engine and custom exceptions
from encryption import AegisEngine, AegisError, IntegrityError, DecryptionError

# --- INITIALIZATION ---
load_dotenv()
app = Flask(__name__)
# Security check for secret key
app.secret_key = os.getenv("FLASK_SECRET_KEY", "aegis-production-fallback-key-9988")

# Core Engine Components
engine = AegisEngine()
PINATA_JWT = os.getenv("PINATA_JWT")

# --- PROFESSIONAL AUDIT LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("vault_audit.log"),
        logging.StreamHandler()
    ]
)

# --- LOG ROTATION LOGIC ---
def rotate_logs():
    """Wipes the audit log every 24 hours to maintain statelessness"""
    with open('vault_audit.log', 'w') as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SYSTEM: 24h Log Rotation Executed. Previous logs purged.\n")
    logging.info("Audit logs rotated successfully.")

scheduler = BackgroundScheduler()
scheduler.add_job(func=rotate_logs, trigger="interval", hours=24)
scheduler.start()

# --- OS RESOURCE MONITORING (Background Thread) ---
def monitor_system_resources():
    """Background thread for OS-level resource tracking."""
    while True:
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        logging.info(f"System Health Update -> CPU: {cpu}% | RAM: {ram}%")
        time.sleep(60)

threading.Thread(target=monitor_system_resources, daemon=True).start()

# --- SECURITY UTILITIES ---
def is_strong_password(password):
    if len(password) < 12:
        return False
    has_digit = any(char.isdigit() for char in password)
    has_special = any(not char.isalnum() for char in password)
    return has_digit and has_special

def sanitize_cid(cid):
    return re.match(r"^[a-zA-Z0-9]{46,59}$", cid)

# --- SECURITY & RATE LIMITING ---
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://",
)

# --- DASHBOARD API ROUTES ---

@app.route('/api/download_audit')
def download_audit():
    """Allows the operator to download the current security trail"""
    try:
        if os.path.exists('vault_audit.log'):
            return send_file('vault_audit.log', as_attachment=True)
        return jsonify({"error": "Log file not generated yet"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/clear_cache', methods=['POST'])
def clear_cache():
    """Force releases system memory back to the OS"""
    initial_mem = psutil.virtual_memory().percent
    collected = gc.collect()
    final_mem = psutil.virtual_memory().percent
    
    logging.info(f"Manual RAM Purge: {collected} objects cleared. RAM {initial_mem}% -> {final_mem}%")
    return jsonify({
        "status": "Purge Complete",
        "objects_cleared": collected,
        "memory_before": initial_mem,
        "memory_after": final_mem
    })

# --- EXISTING TELEMETRY & WEB ROUTES ---

@app.route('/api/status')
def get_status():
    return jsonify({
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    })

@app.route('/')
def landing():
    return render_template('main_landing.html')

@app.route('/vault')
def vault_terminal():
    return render_template('index.html')

# --- CORE API ENDPOINTS ---

@app.route('/api/encrypt', methods=['POST'])
@limiter.limit("20 per minute")
def encrypt_local():
    file = request.files.get('file')
    password = request.form.get("password")
    if not file or not password:
        return jsonify({"error": "Missing file or password"}), 400
    if not is_strong_password(password):
        return jsonify({"error": "Security Alert: Weak password."}), 400

    try:
        raw_data = file.read()
        enc_data = engine.encrypt(raw_data, password)
        del raw_data
        gc.collect() 
        logging.info(f"Local Encryption Successful: {file.filename}")
        return send_file(BytesIO(enc_data), download_name=f"{file.filename}.aegis", as_attachment=True)
    except Exception as e:
        logging.error(f"Encryption Failure: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
@limiter.limit("20 per minute")
def decrypt_local():
    file = request.files.get('file')
    password = request.form.get("password")
    if not file or not password:
        return jsonify({"error": "Missing file or password"}), 400
        
    try:
        raw_cipher = file.read()
        dec_data = engine.decrypt(raw_cipher, password)
        del raw_cipher
        gc.collect()
        logging.info(f"Local Decryption Successful: {file.filename}")
        return send_file(BytesIO(dec_data), download_name="decrypted_file", as_attachment=True)
    except (DecryptionError, IntegrityError):
        logging.warning("Security Fault: Unauthorized decryption attempt.")
        return jsonify({"error": "Security Fault: Invalid Key or Tampered Data"}), 403
    except Exception as e:
        logging.error(f"Decryption Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/encrypt_cloud', methods=['POST'])
@limiter.limit("10 per minute")
def encrypt_cloud():
    file = request.files.get('file')
    password = request.form.get("password")
    if not file or not password:
        return jsonify({"error": "File and password required"}), 400

    try:
        raw_data = file.read()
        enc_data = engine.encrypt(raw_data, password)
        cid = engine.upload_to_ipfs(enc_data, f"{file.filename}.aegis")
        
        # Explicitly clear buffers for statelessness
        del raw_data
        del enc_data
        gc.collect()

        if cid:
            logging.info(f"Cloud Broadcast Success: {cid}")
            return jsonify({"success": True, "cid": cid})
        return jsonify({"error": "IPFS Provider Error"}), 500
    except Exception as e:
        logging.error(f"Cloud Broadcast Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/decrypt_cid', methods=['POST'])
@limiter.limit("10 per minute")
def decrypt_cid():
    cid = request.form.get("cid", "").strip()
    password = request.form.get("password", "").strip()
    if not cid or not password or not sanitize_cid(cid):
        return jsonify({"error": "Invalid Input Credentials"}), 400

    try:
        enc_blob = engine.fetch_from_ipfs(cid)
        if not enc_blob:
            return jsonify({"error": "CID not found"}), 404
            
        dec_data = engine.decrypt(enc_blob, password)
        
        # Auto-Burn Logic: Unpin from Pinata
        url = f"https://api.pinata.cloud/pinning/unpin/{cid}"
        headers = {"Authorization": f"Bearer {PINATA_JWT}"}
        burn_request = requests.delete(url, headers=headers)
        
        if burn_request.status_code == 200:
            logging.info(f"Auto-Burn Triggered: CID {cid} unpinned successfully.")
        else:
            logging.warning(f"Auto-Burn Failure: Could not unpin {cid}. Check API permissions.")

        # Final memory cleanup
        del enc_blob
        gc.collect()
        
        logging.info(f"Cloud Recover & Burn Successful: {cid}")
        return send_file(BytesIO(dec_data), download_name="cloud_recovered", as_attachment=True)
    except Exception as e:
        logging.error(f"Cloud Recovery Failed: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    # HOST 0.0.0.0 is critical for Docker & Ngrok accessibility
    logging.info("AEGIS VAULT v2.5 SYSTEM ONLINE")
    app.run(debug=True, host='0.0.0.0', port=5000)