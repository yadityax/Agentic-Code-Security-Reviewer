from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)
BASE = (Path(__file__).parent / "files").resolve()


@app.route("/download")
def download():
    target = (BASE / request.args.get("name", "")).resolve()
    if not target.is_relative_to(BASE) or not target.is_file():
        abort(404)
    return target.read_text()
