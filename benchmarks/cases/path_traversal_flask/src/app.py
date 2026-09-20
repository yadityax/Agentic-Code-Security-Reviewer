import os

from flask import Flask, request

app = Flask(__name__)
BASE = os.path.join(os.path.dirname(__file__), "files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    with open(os.path.join(BASE, name)) as fh:
        return fh.read()
