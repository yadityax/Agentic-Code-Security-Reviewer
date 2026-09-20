import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/load", methods=["POST"])
def load():
    blob = base64.b64decode(request.form["data"])
    obj = pickle.loads(blob)
    return {"type": type(obj).__name__}
