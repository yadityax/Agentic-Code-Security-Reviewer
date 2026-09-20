import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_config():
    cfg = yaml.load(request.data, Loader=yaml.Loader)
    return {"keys": sorted(cfg)}
