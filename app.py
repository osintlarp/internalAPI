import string
import random
import json
from flask import Flask, request, jsonify
from cprint import info, success, error

app = Flask(__name__)

def generate_x_decode_token():
    hex_chars = string.hexdigits.upper()[:16]
    sections = [8, 4, 4, 4, 12]
    parts = [''.join(random.choice(hex_chars) for _ in range(n)) for n in sections]
    return '-'.join(parts)

def generate_authorization_token():
    hex_chars = string.hexdigits.lower()[:16]
    return ''.join(random.choice(hex_chars) for _ in range(96))

X_DECODE_TOKEN = generate_x_decode_token()
AUTHORIZATION_TOKEN = generate_authorization_token()

info(f"x-decode-token: {X_DECODE_TOKEN}")
info(f"authorization: {AUTHORIZATION_TOKEN}")

def check_tokens():
    x_decode = request.headers.get('x-decode-token')
    auth = request.headers.get('authorization')
    if x_decode != X_DECODE_TOKEN or auth != AUTHORIZATION_TOKEN:
        error(f"Unauthorized request from {request.remote_addr}")
        return False
    return True

@app.route("/v1/users/usermap")
def usermap():
    if not check_tokens():
        return jsonify({"error": "Invalid or missing tokens"}), 401
    try:
        with open("/root/map/user_map.json", "r") as f:
            data = json.load(f)
        success(f"Authorized request from {request.remote_addr} accessed /v1/users/usermap")
        return jsonify(data)
    except Exception as e:
        error(f"Error reading user_map.json: {e}")
        return jsonify({"error": "Failed to read user map"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
