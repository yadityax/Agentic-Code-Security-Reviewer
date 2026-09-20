import sqlite3

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE items (id INTEGER, label TEXT)")
conn.execute("INSERT INTO items VALUES (1, 'pen'), (2, 'ink')")


def find_item(item_id):
    query = "SELECT id, label FROM items WHERE id = " + item_id
    return conn.execute(query).fetchall()


if __name__ == "__main__":
    print(find_item(input("id: ")))
