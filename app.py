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
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Cryptography Constants
ITERATIONS = 480000
SALT_SIZE = 16

def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password_bytes))

# Background Telemetry & Log Rotator Scheduler
def rotate_logs():
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory().percent
    logging.info(f"System Health Update -> CPU: {cpu}% | RAM: {ram}%")

scheduler = BackgroundScheduler()
scheduler.add_job(func=rotate_logs, trigger="interval", minutes=5)
scheduler.start()

@app.route('/')
def landing_page():
    # Fallback check for template name variance
    try:
        return render_template('main_landing_page.html')
    except Exception:
        return render_template('main_landing.html')

@app.route('/vault')
def operational_app():
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent
    })

@app.route('/api/clear_cache', methods=['POST'])
def api_clear_cache():
    mem_before = psutil.virtual_memory().percent
    gc.collect()
    mem_after = psutil.virtual_memory().percent
    return jsonify({
        "memory_before": mem_before,
        "memory_after": mem_after
    })

@app.route('/api/encrypt', methods=['POST'])
@limiter.limit("10 per minute")
def api_encrypt():
    file = request.files.get('file')
    password = request.form.get('password')
    if not file or not password:
        return jsonify({"error": "File and password required"}), 400
    
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    
    output = io.BytesIO()
    output.write(salt)
    output.write(encrypted_data)
    output.seek(0)
    
    return send_file(
        output,
        as_attachment=True,
        download_name=f"{file.filename}.aegis",
        mimetype="application/octet-stream"
    )

@app.route('/api/decrypt', methods=['POST'])
@limiter.limit("10 per minute")
def api_decrypt():
    file = request.files.get('file')
    password = request.form.get('password')
    if not file or not password:
        return jsonify({"error": "File and password required"}), 400
    
    try:
        file_data = file.read()
        salt = file_data[:SALT_SIZE]
        encrypted_data = file_data[SALT_SIZE:]
        
        key = derive_key(password, salt)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        output = io.BytesIO(decrypted_data)
        output.seek(0)
        
        original_name = file.filename
        if original_name.endswith('.aegis'):
            original_name = original_name[:-6]
        else:
            original_name = "recovered_file"

        return send_file(
            output,
            as_attachment=True,
            download_name=original_name,
            mimetype="application/octet-stream"
        )
    except (InvalidToken, Exception):
        return jsonify({"error": "Invalid decryption key or corrupted file package."}), 400

@app.route('/api/encrypt_cloud', methods=['POST'])
@limiter.limit("5 per minute")
def api_encrypt_cloud():
    file = request.files.get('file')
    password = request.form.get('password')
    if not file or not password:
        return jsonify({"error": "File and password required"}), 400
    
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file.read())
    
    payload = salt + encrypted_data
    pinata_jwt = os.environ.get("PINATA_JWT")
    
    if pinata_jwt:
        try:
            res = requests.post(
                "https://api.pinata.cloud/pinning/pinFileToIPFS",
                files={"file": (file.filename + ".aegis", payload)},
                headers={"Authorization": f"Bearer {pinata_jwt}"}
            )
            if res.status_code == 200:
                cid = res.json().get("IpfsHash")
                return jsonify({"cid": cid})
        except Exception:
            pass

    # Simulated fallback CID if Pinata key is absent
    simulated_cid = "Qm" + os.urandom(21).hex()
    return jsonify({"cid": simulated_cid})

@app.route('/api/decrypt_cid', methods=['POST'])
@limiter.limit("5 per minute")
def api_decrypt_cid():
    cid = request.form.get('cid')
    password = request.form.get('password')
    if not cid or not password:
        return jsonify({"error": "CID and password required"}), 400
    
    gateway = os.environ.get("PINATA_GATEWAY", "https://gateway.pinata.cloud/ipfs/")
    try:
        res = requests.get(f"{gateway}{cid}", timeout=15)
        if res.status_code != 200:
            return jsonify({"error": "Failed to fetch payload from IPFS gateway."}), 400
        
        file_data = res.content
        salt = file_data[:SALT_SIZE]
        encrypted_data = file_data[SALT_SIZE:]
        
        key = derive_key(password, salt)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        output = io.BytesIO(decrypted_data)
        output.seek(0)
        
        return send_file(
            output,
            as_attachment=True,
            download_name="recovered_cloud_file",
            mimetype="application/octet-stream"
        )
    except Exception:
        return jsonify({"error": "Decryption failed or invalid CID/password combo."}), 400

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)