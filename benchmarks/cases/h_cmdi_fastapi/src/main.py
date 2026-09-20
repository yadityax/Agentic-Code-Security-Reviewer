import os

from fastapi import FastAPI

app = FastAPI()


@app.get("/echo")
def echo(msg: str):
    os.system("echo " + msg + " > /tmp/last_echo.txt")
    return {"ok": True}
