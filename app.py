from flask import Flask, jsonify, request
from cprint import info, error
import random, string, json, os
import hashlib

app = Flask(__name__)

DECODE_TOKEN = "2EEC8489-5C79-08A9-D0E5-1BA0B20F6289"
AUTH_TOKEN = "7d9697226e688cf870d78ce811c2b41cfc6062a4129ec3b38f527f85cacaf73243f39509099becb95f8d5b4e181e28b6"
QUERY_FILE = "queries.json"

def load_persisted_queries():
    if not os.path.exists(QUERY_FILE):
        return {}
    with open(QUERY_FILE) as f:
        return json.load(f)

def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()

@app.route("/v1/users", methods=["POST"])
def graphql_persisted_query():
    header_decode = request.headers.get("x-decode-token")
    header_auth = request.headers.get("authorization")
    if header_decode != DECODE_TOKEN or header_auth != AUTH_TOKEN:
        return jsonify({"data":null,"errors":[{"message":"unauthorized"}]}), 401

    try:
        body = request.get_json(force=True)
    except:
        return jsonify({"errors": [{"message": "Invalid JSON body"}]}), 400

    extensions = body.get("extensions", {}).get("persistedQuery", {})
    sha = extensions.get("sha256Hash")
    op_name = body.get("operationName")
    variables = body.get("variables", {})
    queries = load_persisted_queries()

    if not sha or sha not in queries:
        return jsonify({"errors": [{"message": "Unknown or missing persisted query"}]}), 400

    query_data = queries[sha]
    if op_name != query_data.get("name"):
        return jsonify({"errors": [{"message": "Operation name mismatch"}]}), 400

    action = query_data.get("action")

    if action == "list_users":
        base_path = "/var/www/users"
        if not os.path.exists(base_path):
            return jsonify({"errors": [{"message": "Directory not found"}]}), 404
        user_list = []
        for f in os.listdir(base_path):
            if os.path.isfile(os.path.join(base_path, f)) and f.endswith(".json"):
                try:
                    with open(os.path.join(base_path, f)) as jf:
                        data = json.load(jf)
                        if "username" in data:
                            user_list.append(data["username"])
                except:
                    continue
        return jsonify({"data": {"GetUserList": user_list}})

    if action == "get_user_map":
        include_api = variables.get("input", {}).get("includeAPI", True)
        map_path = "/root/map/user_map.json"
        if not os.path.exists(map_path):
            return jsonify({"errors": [{"message": "File not found"}]}), 404
        with open(map_path) as f:
            data = json.load(f)
        if not include_api:
            for key in data:
                if "api_key" in data[key]:
                    del data[key]["api_key"]
        return jsonify({"data": {"GetUserMap": data}})

    return jsonify({"errors": [{"message": "Unknown action"}]}), 400

@app.route("/v1/user/<user_id>", methods=["POST"])
def get_user_info(user_id):
    header_decode = request.headers.get("x-decode-token")
    header_auth = request.headers.get("authorization")
    if header_decode != DECODE_TOKEN or header_auth != AUTH_TOKEN:
        return jsonify({"errors": [{"message": "Invalid or missing tokens"}]}), 401

    try:
        body = request.get_json(force=True)
    except:
        return jsonify({"errors": [{"message": "Invalid JSON body"}]}), 400

    extensions = body.get("extensions", {}).get("persistedQuery", {})
    sha = extensions.get("sha256Hash")
    op_name = body.get("operationName")
    variables = body.get("variables", {})
    queries = load_persisted_queries()

    if not sha or sha not in queries:
        return jsonify({"errors": [{"message": "Unknown or missing persisted query"}]}), 400

    query_data = queries[sha]
    if op_name != query_data.get("name") or query_data.get("action") != "get_user_info":
        return jsonify({"errors": [{"message": "Operation mismatch"}]}), 400

    input_data = variables.get("input", {})
    include_api = input_data.get("includeAPI", False)
    include_sessions = input_data.get("includeSessions", False)
    include_useragent = input_data.get("includeUserAgent", False)
    include_permissions = input_data.get("includePermissions", True)

    file_path = f"/var/www/users/{user_id}.json"
    if not os.path.exists(file_path):
        return jsonify({"errors": [{"message": "User not found"}]}), 404

    try:
        with open(file_path) as f:
            user_data = json.load(f)
    except Exception as e:
        return jsonify({"errors": [{"message": f"Failed to load user data: {str(e)}"}]}), 500

    if not include_api and "api_key" in user_data:
        del user_data["api_key"]

    if not include_sessions and "session_token" in user_data:
        del user_data["session_token"]
    elif include_sessions and "session_token" in user_data:
        hashed_sessions = []
        for s in user_data["session_token"]:
            s_copy = s.copy()
            if "session_token" in s_copy:
                s_copy["session_token"] = hash_token(s_copy["session_token"])
            hashed_sessions.append(s_copy)
        user_data["session_token"] = hashed_sessions

    if not include_useragent and "user_agent" in user_data:
        del user_data["user_agent"]

    if not include_permissions and "permissions" in user_data:
        del user_data["permissions"]

    return jsonify({"data": {"GetUserInfo": user_data}})

    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
