from typing import Optional
import base64
import hmac
import hashlib
import json

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = '034b6f69010c98c876ab80df5b55800908776fdc26fd91ef23150ee338716637'
PASSWORD_SALT = '6da9af4f223fdcabfb7150074e87c60db898f76ac0715aef19175bbbf93378f6'

def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return password_hash == stored_password_hash

users = {
    'alex@user.com': {
        'name': 'Alex',
        'password': 'cac0d1245347fc33e91fc0e277f432f5160d2d732c250f83f176b4173617a438',
        'balance': 100_000,
    },
    'petr@user.com': {
        'name': 'Petr',
        'password': 'cf5215c7c85d71013e7612d6397c888a61a2ba789ed5f5b26011cd34355abd0a',
        'balance': 555_555,
    },
}


@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')  
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(
        f'Привет, {users[valid_username]["name"]}!<br />'
        f'Баланс: {users[valid_username]["balance"]}', 
        media_type='text/html'
        )

@app.post('/login')
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                'success': False,
                'message': 'Я вас не',
            }),
            media_type='application/json'
            )
    response = Response(
        json.dumps({
            'success': True,
            'message': f'Привет {user["name"]}!<br />Баланс: {user["balance"]}'
        }), 
        media_type='application/json'
        )
    username_signed = base64.b64encode(username.encode()).decode() + '.' +\
        sign_data(username)
    response.set_cookie(key='username', value=username_signed)
    return response
