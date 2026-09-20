from flask import Flask, jsonify, request

app = Flask(__name__)
USERS = {"alice": {"role": "user"}, "root": {"role": "admin"}}


@app.route("/admin/users")
def list_users():
    return jsonify(sorted(USERS))


@app.route("/profile")
def profile():
    user = request.headers.get("X-User")
    return jsonify(USERS.get(user, {}))
