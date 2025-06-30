import json
from flask import Flask, request, jsonify
import hashlib
import base64
from Crypto.Cipher import AES

class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()
    @staticmethod
    def str_to_bytes(data):
        u_type = type(b"".decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]
    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))
    def decrypt_string(self, enc):
        enc = base64.b64decode(enc)
        return self.decrypt(enc).decode('utf8')

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({"message": "Hello from Render + Flask!"})

@app.route("/decrypt", methods=["GET"])
def decrypt_route():
    ciphertext = request.args.get("ciphertext")
    key = request.args.get("key")
    if not ciphertext or not key:
        return jsonify({"error": "Missing ciphertext or key"}), 400
    try:
        cipher = AESCipher(key)
        plaintext = cipher.decrypt_string(ciphertext)
        # Thử parse plaintext thành JSON object
        try:
            parsed = json.loads(plaintext)
            return jsonify(parsed)
        except Exception:
            # Nếu không phải JSON, trả về dưới dạng text cũ
            return jsonify({"plaintext": plaintext})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run()
