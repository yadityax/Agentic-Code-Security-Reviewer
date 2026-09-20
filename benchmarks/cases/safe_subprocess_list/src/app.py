import subprocess

from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED = {"date", "uptime"}


@app.route("/run")
def run():
    cmd = request.args.get("cmd", "")
    if cmd not in ALLOWED:
        abort(400)
    return subprocess.run([cmd], capture_output=True, text=True, check=False).stdout
