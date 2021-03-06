from datetime import datetime
import json

from flask import Flask, request
from flask_mail import Mail
from flasgger import Swagger, swag_from
from marshmallow import ValidationError

from db.db import init_db, db
from db.init_tables import create_tables
from db import redis
from service.sign_up import sign_up_user
from service.log_in import log_in_user
from service.auth import check_auth_decorator, check_permissions_decorator
from service.change_pwd import change_pwd
from service.history import get_login_history
from service.change_login import change_login
from service.confirm import confirm_email
from common import settings
from common.errors import ServiceError
from schemas.change_pwd import NewPassword
from schemas.login import LoginSchema
from schemas.sign_up import SignUpSchema
from schemas.history import HistorySchema
from schemas.change_login import NewLogin
from schemas.create_su import SUSchema


app = Flask(__name__)
app.config.from_object(settings)
mail = Mail(app)

swagger = Swagger(app)


@app.route('/', methods=['POST'])
@swag_from('schemas_docs/auth.yml')
@check_permissions_decorator()
def auth(token_data):
    """
    Проверка валидности токена авторизации
    """
    return token_data


@app.route('/login', methods=['POST'])
@swag_from('schemas_docs/login.yml')
def login():
    """
    Авторизация пользователя по логину или email. Получение токена сессии.
    """
    session = db.session
    req = request.get_json()

    try:
        LoginSchema().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    try:
        gen_token = log_in_user(session, req, req.get('device', 'web'))
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': {"token": gen_token}}


@app.route('/sign-up', methods=['POST'])
@swag_from('schemas_docs/sign_up.yml')
def sign_up():
    """
    Регистрация пользователя по email.
    """
    session = db.session
    req = request.get_json()

    try:
        SignUpSchema().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    try:
        sign_up_user(mail, session, req)
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': "Account successfully created. Please, confirm your email."}


@app.route('/confirm/<token>')
@swag_from('schemas_docs/confirm.yml')
def confirm_email_route(token):
    """
    Подтвердждение email
    """
    session = db.session

    try:
        confirm_email(session, token)
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': 'You successfully confirmed your email. Please, log in.'}


@app.route('/logout', methods=['POST'])
@check_auth_decorator
@swag_from('schemas_docs/logout.yml')
def logout(token_data):
    """
    Выход из сессии
    """
    token = request.headers.get('Authorization')

    token_data['logged_out'] = datetime.now().timestamp()

    redis.redis.set(token, json.dumps(token_data), settings.REDIS_EXPIRE_TIME)

    return {'error': None, 'result': 'You successfully logged out'}


@app.route('/change_password', methods=['POST'])
@check_auth_decorator
@swag_from('schemas_docs/change_password.yml')
def change_password(token_data):
    """
    Смена пароля пользователя
    """
    session = db.session
    req = request.get_json()

    try:
        NewPassword().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    try:
        change = change_pwd(session, token_data.get('user'), req.get('new_password'))
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': change}


@app.route('/change_login', methods=['POST'])
@check_auth_decorator
@swag_from('schemas_docs/change_login.yml')
def set_new_login(token_data):
    """
    Смена логина пользователя
    """
    session = db.session
    req = request.get_json()

    try:
        NewLogin().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    try:
        change = change_login(session, token_data.get('user'), req.get('new_login'))
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': change}


@app.route('/history', methods=['POST'])
@check_auth_decorator
@swag_from('schemas_docs/history.yml')
def history(token_data):
    """
    Получение истоиии входов пользователя
    """
    session = db.session
    req = request.get_json()

    try:
        HistorySchema().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    try:
        user_history = get_login_history(session, token_data.get('user'), req.get('date_start'), req.get('date_end'))
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': user_history}


@app.route('/create_superuser', methods=['POST'])
@check_permissions_decorator(['full'])
def create_superuser(token_data):
    session = db.session
    req = request.get_json()

    try:
        SUSchema().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    req['roles'] = ['super_user']

    try:
        sign_up_user(mail, session, req)
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': "Account successfully created. Please, confirm your email."}


def main():
    init_db(app)
    with app.app_context():
        create_tables()
    redis.redis = redis.RedisBase(settings.REDIS_HOST, settings.REDIS_PORT, settings.SESSION_REDIS_DB)
    redis.redis.connect()
    app.run(host='0.0.0.0')
    redis.redis.close_connection()


if __name__ == '__main__':
    main()
