import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    out = subprocess.run("echo pinging " + host, shell=True, capture_output=True, text=True)
    return out.stdout
