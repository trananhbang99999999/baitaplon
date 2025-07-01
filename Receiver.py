from flask import Flask, render_template, flash, redirect, url_for, request, send_file
import os, json, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, DES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

app = Flask(__name__)
app.secret_key = "receiverkey"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load RSA keys
try:
    with open(os.path.join(BASE_DIR, "receiver_private.pem"), "rb") as f:
        receiver_priv = RSA.import_key(f.read())
    with open(os.path.join(BASE_DIR, "sender_public.pem"), "rb") as f:
        sender_pub = RSA.import_key(f.read())
except Exception as e:
    print(f"❌ Lỗi khi tải khóa: {e}")
    receiver_priv = None
    sender_pub = None

SESSION_STATE = {
    "key": None,
    "metadata": None,
    "encrypted_key": None,
    "output_file": None
}

@app.route("/")
def index():
    return render_template("receiver_index.html")

@app.route("/part/<int:part_id>")
def view_part(part_id):
    try:
        path = os.path.join(BASE_DIR, f"part{part_id}.json")
        if not os.path.exists(path):
            flash(f"❌ Không tìm thấy part{part_id}.json")
            return redirect(url_for("index"))

        with open(path) as f:
            part_data = json.load(f)

        return render_template("view_part.html", part=part_data, part_id=part_id)

    except Exception as e:
        flash(f"Lỗi khi đọc part {part_id}: {e}")
        return redirect(url_for("index"))

@app.route("/receive/handshake", methods=["GET"])
def receive_handshake():
    try:
        handshake_path = os.path.join(BASE_DIR, "handshake_send.json")
        if not os.path.exists(handshake_path):
            flash("❌ Không tìm thấy file handshake_send.json")
            return redirect(url_for("index"))

        with open(handshake_path) as f:
            hello = json.load(f)
        if hello.get("hello") != "Hello!":
            flash("❌ Handshake không hợp lệ.")
        else:
            flash("✅ Handshake thành công. Người nhận trả lời: Ready!")
    except Exception as e:
        flash(f"❌ Lỗi khi xử lý handshake: {e}")
    return redirect(url_for("index"))

@app.route("/receive/metadata", methods=["GET"])
def receive_metadata():
    try:
        metadata_path = os.path.join(BASE_DIR, "handshake.json")
        if not os.path.exists(metadata_path):
            flash("❌ Không tìm thấy file handshake.json")
            return redirect(url_for("index"))

        with open(metadata_path) as f:
            hs = json.load(f)

        metadata = hs["metadata"]
        sig = base64.b64decode(hs["signature"])
        encrypted_key = base64.b64decode(hs["encrypted_key"])

        pkcs1_15.new(sender_pub).verify(SHA512.new(metadata.encode()), sig)
        session_key = PKCS1_v1_5.new(receiver_priv).decrypt(encrypted_key, None)

        if not session_key:
            flash("❌ Session key không giải mã được.")
            return redirect(url_for("index"))

        if len(session_key) != 8:
            flash(f"❌ Session key không hợp lệ ({len(session_key)} bytes).")
            return redirect(url_for("index"))

        filename = metadata.split("|")[0]
        SESSION_STATE["key"] = session_key
        SESSION_STATE["metadata"] = metadata
        SESSION_STATE["encrypted_key"] = encrypted_key
        SESSION_STATE["output_file"] = filename

        flash("✅ Metadata hợp lệ và Session Key đã được giải mã.")
    except Exception as e:
        flash(f"❌ Lỗi xác minh metadata: {e}")
    return redirect(url_for("index"))

@app.route("/receive/decrypt", methods=["GET"])
def receive_decrypt():
    try:
        session_key = SESSION_STATE.get("key")
        filename = SESSION_STATE.get("output_file")
        if not session_key or len(session_key) != 8:
            flash(f"❌ Session key không hợp lệ ({len(session_key) if session_key else 0} bytes).")
            return redirect(url_for("index"))

        combined_data = b""
        for i in range(1, 4):
            part_path = os.path.join(BASE_DIR, f"part{i}.json")
            if not os.path.exists(part_path):
                flash(f"❌ Không tìm thấy part{i}.json")
                return redirect(url_for("index"))

            with open(part_path) as f:
                part = json.load(f)

            iv = base64.b64decode(part["iv"])
            cipher_text = base64.b64decode(part["cipher"])
            sig_part = base64.b64decode(part["sig"])
            expected_hash = part["hash"]

            h = SHA512.new(iv + cipher_text)
            if h.hexdigest() != expected_hash:
                flash(f"❌ Phần {i}: Hash sai.")
                return redirect(url_for("index"))

            pkcs1_15.new(sender_pub).verify(h, sig_part)
            cipher = DES.new(session_key, DES.MODE_CFB, iv)
            plaintext = cipher.decrypt(cipher_text)
            combined_data += plaintext

        output_path = os.path.join(BASE_DIR, filename)
        with open(output_path, "wb") as f:
            f.write(combined_data)

        flash("✅ Giải mã và kiểm tra tính toàn vẹn thành công. File đã được lưu để tải về.")
    except Exception as e:
        flash(f"❌ Lỗi khi giải mã và xác thực dữ liệu: {e}")
    return redirect(url_for("index"))

@app.route("/download", methods=["GET"])
def download_file():
    try:
        filename = SESSION_STATE.get("output_file")
        if not filename:
            flash("❌ Chưa có file để tải.")
            return redirect(url_for("index"))

        file_path = os.path.join(BASE_DIR, filename)
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        flash(f"❌ Lỗi khi tải file: {e}")
        return redirect(url_for("index"))

@app.route("/upload", methods=["POST"])
def upload_handler():
    try:
        data = request.get_json()
        if not data:
            return {"status": "fail", "reason": "No JSON received"}, 400

        if "hello" in data:
            with open("handshake_send.json", "w") as f:
                json.dump(data, f)
            return {"status": "ok", "message": "Handshake received"}

        elif "metadata" in data and "signature" in data and "encrypted_key" in data:
            with open("handshake.json", "w") as f:
                json.dump(data, f)
            return {"status": "ok", "message": "Metadata received"}

        elif "part" in data and "data" in data:
            part_number = data["part"]
            with open(f"part{part_number}.json", "w") as f:
                json.dump(data["data"], f)
            return {"status": "ok", "message": f"Part {part_number} received"}

        else:
            return {"status": "fail", "reason": "Unknown data structure"}, 400

    except Exception as e:
        return {"status": "error", "message": str(e)}, 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)
