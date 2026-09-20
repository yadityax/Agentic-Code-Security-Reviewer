import sqlite3

from flask import Flask, request

app = Flask(__name__)
con = sqlite3.connect(":memory:", check_same_thread=False)
con.execute("CREATE TABLE products (sku TEXT, price REAL)")
con.execute("INSERT INTO products VALUES ('A1', 9.5), ('B2', 20)")


@app.get("/price")
def price():
    sku = request.args["sku"]
    cur = con.cursor()
    cur.execute("SELECT price FROM products WHERE sku = '{}'".format(sku))
    row = cur.fetchone()
    return {"price": row[0] if row else None}
