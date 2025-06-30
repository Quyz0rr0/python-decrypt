import hashlib
import base64
from Crypto.Cipher import AES

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

def handler(request, response):
    # Nhận ciphertext và key từ query hoặc body (form-data)
    data = request.query
    ciphertext = data.get("ciphertext") or (request.body and request.body.get("ciphertext"))
    key = data.get("key") or (request.body and request.body.get("key"))

    if not ciphertext or not key:
        return response.json({
            "success": False,
            "error": "Missing 'ciphertext' or 'key' parameter"
        }, status=400)
    try:
        plaintext = decrypt_aes(ciphertext, key)
        return response.json({
            "success": True,
            "plaintext": plaintext
        })
    except Exception as e:
        return response.json({
            "success": False,
            "error": str(e)
        }, status=500)
