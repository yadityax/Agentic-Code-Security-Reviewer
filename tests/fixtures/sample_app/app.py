import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
AWS_KEY = "AKIAZ5QW7NRTKLM4PXV2"
DB_API_TOKEN = "9f8e7d6c5b4a39281706f5e4d3c2b1a0aa"


@app.route("/user")
def user():
    name = request.args.get("name")
    conn = sqlite3.connect("db.sqlite")
    return str(conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c1 " + host, shell=True)
