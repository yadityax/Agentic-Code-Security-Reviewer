import html

from flask import Flask, request

app = Flask(__name__)


@app.route("/hi")
def hi():
    return "<p>Hi " + html.escape(request.args.get("n", "")) + "</p>"
