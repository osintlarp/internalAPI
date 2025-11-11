from flask import Flask, jsonify, request
from cprint import info, error
import random, string, json, os

app = Flask(__name__)

DECODE_TOKEN = "2EEC8489-5C79-08A9-D0E5-1BA0B20F6289"
AUTH_TOKEN = "7d9697226e688cf870d78ce811c2b41cfc6062a4129ec3b38f527f85cacaf73243f39509099becb95f8d5b4e181e28b6"

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
