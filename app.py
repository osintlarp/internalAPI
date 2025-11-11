from flask import Flask, jsonify, request
from cprint import info, error
import random, string, json, os

app = Flask(__name__)

def generate_first():
    hex_chars = string.hexdigits.upper()[:16]
    sections = [8, 4, 4, 4, 12]
    parts = [''.join(random.choice(hex_chars) for _ in range(n)) for n in sections]
    return '-'.join(parts)

def generate_second():
    hex_chars = string.hexdigits.lower()[:16]
    return ''.join(random.choice(hex_chars) for _ in range(96))

DECODE_TOKEN = generate_first()
AUTH_TOKEN = generate_second()

info(f"x-decode-token: {DECODE_TOKEN}")
info(f"authorization: {AUTH_TOKEN}")

@app.route("/v1/users/usermap")
def usermap():
    header_decode = request.headers.get("x-decode-token")
    header_auth = request.headers.get("authorization")

    if header_decode != DECODE_TOKEN or header_auth != AUTH_TOKEN:
        return jsonify({"error": "Invalid or missing tokens"}), 401

    if not os.path.exists("/root/map/user_map.json"):
        return jsonify({"error": "File not found"}), 404

    with open("/root/map/user_map.json") as f:
        data = json.load(f)
    return jsonify(data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
