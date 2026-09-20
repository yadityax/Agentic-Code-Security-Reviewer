from flask import Flask, jsonify, request
from sqlalchemy import Column, Integer, String, create_engine, select
from sqlalchemy.orm import Session, declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String)


engine = create_engine("sqlite://")
Base.metadata.create_all(engine)
with Session(engine) as s:
    s.add(User(name="alice"))
    s.commit()
app = Flask(__name__)


@app.route("/u")
def u():
    with Session(engine) as s:
        rows = s.execute(select(User).where(User.name == request.args.get("name", ""))).scalars().all()
        return jsonify([r.name for r in rows])
