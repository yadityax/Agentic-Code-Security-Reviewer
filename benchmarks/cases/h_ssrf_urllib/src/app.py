import urllib.request

from flask import Flask, request

app = Flask(__name__)


@app.route("/preview")
def preview():
    target = request.args.get("link")
    with urllib.request.urlopen(target, timeout=3) as resp:
        return {"bytes": len(resp.read(2000))}
