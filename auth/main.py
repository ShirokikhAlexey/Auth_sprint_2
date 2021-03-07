from datetime import datetime
import json

from flask import Flask, request, render_template, url_for, redirect
from flask_mail import Mail
from flasgger import Swagger, swag_from
from marshmallow import ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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
from service.permissions import create_permission, add_permission_to_role
from service.roles import change_user_roles, create_role
from service.oauth import OAuthSignIn, sign_up_oauth
from common import settings
from common.errors import ServiceError
from schemas.change_pwd import NewPassword
from schemas.login import LoginSchema
from schemas.sign_up import SignUpSchema
from schemas.history import HistorySchema
from schemas.change_login import NewLogin
from schemas.create_su import SUSchema
from schemas.add_permission import AddPermissionSchema
from schemas.add_role import AddRoleSchema
from schemas.add_role_permission import AddPermissionRoleSchema
from schemas.change_roles import ChangeUserRolesSchema


app = Flask(__name__)
app.config.from_object(settings)
mail = Mail(app)

swagger = Swagger(app)

limiter = Limiter(
    app,
    key_func=get_remote_address
)


@app.route('/', methods=['POST'])
@check_permissions_decorator()
@swag_from('schemas_docs/auth.yml')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
def auth(token_data):
    """
    Проверка валидности токена авторизации
    """
    return token_data


@app.route('/login', methods=['POST', 'GET'])
@swag_from('schemas_docs/login.yml')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
def login(device='web'):
    """
    Авторизация пользователя по логину или email. Получение токена сессии.
    """
    session = db.session
    req = request.get_json()
    if request.method == 'GET':
        return render_template('log_in.html', url=url_for('oauth_sign_up', provider='vk', device=device,
                                                          _external=True))

    try:
        LoginSchema().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    if req.get('oauth'):
        return redirect(url_for('oauth_sign_up', provider=req.get('oauth'), device=req.get('device'), _external=True))

    try:
        gen_token = log_in_user(session, req, req.get('device', 'web'))
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': {"token": gen_token}}


@app.route('/sign-up', methods=['POST', 'GET'])
@swag_from('schemas_docs/sign_up.yml')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
def sign_up(device='web'):
    """
    Регистрация пользователя по email.
    """
    session = db.session
    req = request.get_json()
    if request.method == 'GET':
        return render_template('sign_up.html', url=url_for('oauth_sign_up', provider='vk', device=device,
                                                           _external=True))
    try:
        SignUpSchema().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    if req.get('oauth'):
        return redirect(url_for('oauth_sign_up', provider=req.get('oauth'), device=req.get('device'), _external=True))

    try:
        sign_up_user(mail, session, req)
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': "Account successfully created. Please, confirm your email."}


@app.route('/sign-up/<provider>')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
def oauth_sign_up(provider):
    oauth = OAuthSignIn.get_provider(provider)
    oauth.device = request.args['device']
    return oauth.authorize()


@app.route('/callback/<provider>')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
def oauth_callback(provider):
    oauth = OAuthSignIn.get_provider(provider)
    email = oauth.callback()
    session = db.session
    if email is None:
        return {'error': 'Authorization failed', 'result': None}

    try:
        token = sign_up_oauth(session, email, oauth.device)
    except ServiceError as e:
        return {'error': e.msg, 'result': None}
    return {'error': None, 'result': token,
            'msg': "You successfully logged in. Please, change your password and login"}


@app.route('/confirm/<token>')
@swag_from('schemas_docs/confirm.yml')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
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
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
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
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
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
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
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
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
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
@swag_from('schemas_docs/create_superuser.yml')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
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


@app.route('/add_role', methods=['POST'])
@check_permissions_decorator(['full'])
@swag_from('schemas_docs/add_role.yml')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
def add_new_role(token_data):
    session = db.session
    req = request.get_json()

    try:
        AddRoleSchema().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    try:
        create_role(session, req.get('role_name'))
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': "New role successfully created."}


@app.route('/change_user_roles', methods=['POST'])
@check_permissions_decorator(['full'])
@swag_from('schemas_docs/change_user_roles.yml')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
def new_user_roles(token_data):
    session = db.session
    req = request.get_json()

    try:
        ChangeUserRolesSchema().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    try:
        change_user_roles(session, req.get('user_id'), req.get('new_roles'))
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': "You successfully changed user roles."}


@app.route('/create_permission', methods=['POST'])
@check_permissions_decorator(['full'])
@swag_from('schemas_docs/create_permission.yml')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
def add_new_permission(token_data):
    session = db.session
    req = request.get_json()

    try:
        AddPermissionSchema().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    try:
        create_permission(session, req.get('permission_name'))
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': "New permission successfully created."}


@app.route('/add_permission_to_role', methods=['POST'])
@check_permissions_decorator(['full'])
@swag_from('schemas_docs/add_permission_to_role.yml')
@limiter.limit(settings.REQUEST_LIMIT_PER_MINUTE)
def new_role_permission(token_data):
    session = db.session
    req = request.get_json()

    try:
        AddPermissionRoleSchema().load(req)
    except ValidationError as e:
        return {'error': e.messages, 'result': None}

    try:
        add_permission_to_role(session, req.get('permission_name'), req.get('role_name'))
    except ServiceError as e:
        return {'error': e.msg, 'result': None}

    return {'error': None, 'result': "You successfully added permission to role."}


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
