from typing import Optional
from fastapi import FastAPI
from pydantic import BaseModel
import jwt
import datetime
import settings
import time
import bcrypt
import sqlite3

SECRET_KEY = settings.SECRET_KEY

def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

def create_jwt(content: str):
    payload = {
        "sub": content,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=180),
        "iat": datetime.datetime.utcnow(),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token


def verify_jwt(token: str):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return "토큰 만료됨"
    except jwt.InvalidTokenError:
        return "유효하지 않은 토큰"
    
def start_db():
    con = sqlite3.connect("db.db")
    cur = con.cursor()
    return con, cur

def get_user(userid: str):
    con, cur = start_db()
    cur.execute("SELECT * FROM USER WHERE id = ?", (userid,))
    user = cur.fetchone()
    con.close()
    return user

    
def add_user(userid: str, nickname: str, password: str, email: Optional[str] = None):
    hashed_password = hash_password(password)
    con, cur = start_db()
    cur.execute("INSERT INTO USER (id, nickname, password, email) VALUES (?, ?, ?, ?)", (userid, nickname, hashed_password, email))
    con.commit()
    con.close()
    return True

app = FastAPI()

@app.get("/check_duplication")
def register(id: str):
    user = get_user(id)
    if user:
        return {"status": True}
    else:
        return {"status": False}

class RegiForm(BaseModel):
    userid: str
    nickname: str
    password: str
    email: Optional[str] = None

@app.post("/register")
def register(item: RegiForm):
    if get_user(item.userid):
        return {"status": "error", "message": "fuk yr id duplication"}
    item_dict = item.model_dump()
    try:
        status = add_user(item.userid, item.nickname, item.password, item.email)
        token = create_jwt(item.userid)
        return {"status": "success", "token": token}
    except Exception as e:
        return {"status": "error", "message": ""}

class LoginForm(BaseModel):
    userid: str
    password: str

@app.post("/login")
def login(item: LoginForm):
    user = get_user(item.userid)
    if not user:
        return {"status": "error", "message": "no such user"}
    if not verify_password(item.password, user[1]):
        return {"status": "error", "message": "wrong password"}
    token = create_jwt(item.userid)
    return {"status": "success", "token": token}

@app.get("/verify_token")
def verify_token(token: str):
    result = verify_jwt(token)
    if isinstance(result, dict):
        return {"status": "success", "data": result}
    else:
        return {"status": "error", "message": result}
