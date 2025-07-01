from flask import Flask, render_template, request, flash
import os, base64, json, requests
from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "securekey"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

RECEIVER_PUB_KEY = os.path.join(BASE_DIR, "receiver_public.pem")
SENDER_PRIV_KEY = os.path.join(BASE_DIR, "sender_private.pem")
RECEIVER_UPLOAD_URL = "http://127.0.0.1:5001/upload"

@app.route("/")
def index():
    return render_template("sender_index.html")

@app.route("/send", methods=["POST"])
def send_file():
    try:
        file = request.files.get("file")
        if not file:
            flash("❌ Vui lòng chọn file.")
            return render_template("sender_index.html")

        filename = secure_filename(file.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(path)

        with open(path, "rb") as f:
            data = f.read()
        session_key = get_random_bytes(8)

        with open(RECEIVER_PUB_KEY, "rb") as f:
            receiver_pub = RSA.import_key(f.read())
        with open(SENDER_PRIV_KEY, "rb") as f:
            sender_priv = RSA.import_key(f.read())

        # Handshake
        requests.post(RECEIVER_UPLOAD_URL, json={"hello": "Hello!"})

        # Metadata
        timestamp = datetime.utcnow().isoformat()
        metadata = f"{filename}|{timestamp}|3"
        meta_hash = SHA512.new(metadata.encode())
        meta_sig = pkcs1_15.new(sender_priv).sign(meta_hash)
        encrypted_session_key = PKCS1_v1_5.new(receiver_pub).encrypt(session_key)

        meta_payload = {
            "metadata": metadata,
            "signature": base64.b64encode(meta_sig).decode(),
            "encrypted_key": base64.b64encode(encrypted_session_key).decode()
        }
        requests.post(RECEIVER_UPLOAD_URL, json=meta_payload)

        # Split file
        part_len = len(data) // 3
        parts = [data[i * part_len:(i + 1) * part_len] for i in range(2)]
        parts.append(data[2 * part_len:])

        for i, part in enumerate(parts):
            iv = get_random_bytes(8)
            cipher = DES.new(session_key, DES.MODE_CFB, iv)
            ciphertext = cipher.encrypt(part)
            h = SHA512.new(iv + ciphertext)
            sig = pkcs1_15.new(sender_priv).sign(h)

            packet = {
                "iv": base64.b64encode(iv).decode(),
                "cipher": base64.b64encode(ciphertext).decode(),
                "hash": h.hexdigest(),
                "sig": base64.b64encode(sig).decode()
            }

            requests.post(RECEIVER_UPLOAD_URL, json={"part": i + 1, "data": packet})

        flash("✅ Gửi file thành công.")
    except Exception as e:
        flash(f"❌ Lỗi gửi: {str(e)}")
    return render_template("sender_index.html")

if __name__ == '__main__':
    app.run(debug=True, port=5000)
