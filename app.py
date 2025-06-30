from flask import Flask, request, jsonify
import hashlib
import base64
from Crypto.Cipher import AES

app = Flask(__name__)

def str_to_bytes(data):
    u_type = type(b"".decode('utf8'))
    if isinstance(data, u_type):
        return data.encode('utf8')
    return data

def _unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def decrypt_aes(ciphertext_b64, key):
    enc = base64.b64decode(ciphertext_b64)
    bs = AES.block_size
    key_digest = hashlib.sha256(str_to_bytes(key)).digest()
    iv = enc[:bs]
    cipher = AES.new(key_digest, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(enc[bs:])
    return _unpad(decrypted).decode('utf8')

@app.route("/")
def home():
    return jsonify({"message": "Hello from Render + Flask!"})

@app.route("/decrypt", methods=["GET"])
def decrypt():
    ciphertext = request.args.get("ciphertext")
    key = request.args.get("key")
    if not ciphertext or not key:
        return jsonify({"error": "Missing ciphertext or key"}), 400
    try:
        plaintext = decrypt_aes(ciphertext, key)
        return jsonify({"plaintext": plaintext})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run()
