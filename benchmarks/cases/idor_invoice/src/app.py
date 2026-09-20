from flask import Flask, abort, jsonify, request

app = Flask(__name__)
INVOICES = {1: {"owner": "alice", "total": 120}, 2: {"owner": "bob", "total": 999}}


def current_user():
    return request.headers.get("X-User", "")


@app.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):
    if not current_user():
        abort(401)
    invoice = INVOICES.get(invoice_id)
    if invoice is None:
        abort(404)
    return jsonify(invoice)
