from typing import Optional
from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response
import hmac
import hashlib
import base64
import json

app = FastAPI()


def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash


users = {
    'Vlad21islav': {
        "name": "Владислав",
        "password": '80d2a5ead9496b1c48d91356abdfc830f62caed2ac082741a15d6e7cb1f2078c',
        "balance": 100_000
    },
    "petr2345": {
        "name": "Пётр",
        "password": '286b9c3e2fa93a9e3ce942242d64531bf6978c022a51543bbb1011d646bd6b2f',
        "balance": 3
    }
}

SECRET_KEY = "84db58039c49230c72218cf6dd23c363c369630eb0d063280f06a09e20946d02"
PASSWORD_SALT = "9a7197b25906f5056abb78f24146616236e1fa8257067b9b76eec82cfb5561cf"


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    try:
        valid_username = get_username_from_signed_string(username)
    except ValueError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(f"Здравствуйте, {user['name']}!<br />Ваш баланс: {user['balance']}", media_type="text/html")


@app.post("/login")
def process_login_page(data: dict = Body(...)):
    print("data is", data)
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(json.dumps({
            "success": False,
            "message": "Неверный никнэйм или пороль"
        }), media_type="application/json")

    response = Response(json.dumps({
        "success": True,
        "message": f"Здравствуйте, {user['name']}!<br />Ваш баланс: {user['balance']}"
    }), media_type="application/json")

    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
