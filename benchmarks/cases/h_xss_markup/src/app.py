from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/greet")
def greet():
    who = request.args.get("who", "guest")
    return Markup("<p>Welcome, %s</p>") % Markup(who)
