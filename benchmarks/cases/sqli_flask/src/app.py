import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
db.execute("INSERT INTO users (name, email) VALUES ('alice', 'a@x.io'), ('bob', 'b@x.io')")


@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    rows = db.execute(f"SELECT id, name, email FROM users WHERE name = '{name}'").fetchall()
    return jsonify(rows)
