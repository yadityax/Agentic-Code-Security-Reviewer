from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return render_template_string("<h1>Hello " + name + "</h1>")
