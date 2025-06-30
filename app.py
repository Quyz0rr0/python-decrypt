from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({"message": "Hello from Render + Flask!"})

# Ví dụ endpoint giải mã
@app.route("/decrypt", methods=["GET"])
def decrypt():
    ciphertext = request.args.get("ciphertext")
    key = request.args.get("key")
    if not ciphertext or not key:
        return jsonify({"error": "Missing ciphertext or key"}), 400
    # Giải mã ở đây...
    return jsonify({"plaintext": "Kết quả giải mã ở đây"})
