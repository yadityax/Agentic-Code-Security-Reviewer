import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
db.execute("INSERT INTO users (name) VALUES ('alice')")
ALLOWED_SORT = {"id": "id", "name": "name"}


@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    order = ALLOWED_SORT.get(request.args.get("sort", "id"), "id")
    rows = db.execute("SELECT id, name FROM users WHERE name = ? ORDER BY " + order, (name,)).fetchall()
    return jsonify(rows)
