from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import random
import string

app = Flask(__name__)

server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
server_public_key = server_private_key.public_key()

client_public_keys = {}


def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


@app.route('/public_key', methods=['GET'])
def get_public_key():
    serialized_public_key = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({"public_key": serialized_public_key.decode()})


@app.route('/register_client_key', methods=['POST'])
def register_client_key():
    data = request.json
    client_id = data.get("client_id")
    public_key_pem = data.get("public_key")

    if not client_id or not public_key_pem:
        return jsonify({"error": "Missing client_id or public_key"}), 400

    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    client_public_keys[client_id] = public_key
    return jsonify({"status": "success"})


@app.route('/verify', methods=['POST'])
def verify_client_signature():
    data = request.json
    client_id = data.get("client_id")
    message = data.get("message")
    signature = data.get("signature")

    if not client_id or not message or not signature:
        return jsonify({"error": "Missing client_id, message, or signature"}), 400

    public_key = client_public_keys.get(client_id)
    if not public_key:
        return jsonify({"error": "Client public key not found"}), 404

    is_valid = verify_signature(public_key, message, signature)
    return jsonify({"is_valid": is_valid})


@app.route('/generate_signed_message', methods=['GET'])
def generate_signed_message():
    random_message = ''.join(random.choices(
        string.ascii_letters + string.digits, k=16))

    signature = sign_message(server_private_key, random_message)

    return jsonify({
        "message": random_message,
        "signature": signature
    })


if __name__ == "__main__":
    app.run(debug=True)
