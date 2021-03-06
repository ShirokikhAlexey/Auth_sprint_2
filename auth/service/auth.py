from functools import wraps

import jwt
from flask import request

from db import redis
from common import settings
from common.errors import ServiceError


def decode_auth_token(key: str, auth_token: str):
    """
    Декодирование токена авторизации
    :param key: секретный ключ
    :param auth_token: токен
    :return:
    """
    try:
        payload = jwt.decode(bytes(auth_token, 'utf-8'), key)
        return payload
    except jwt.ExpiredSignatureError:
        raise ServiceError('Token expired. Please, log in again.')
    except jwt.InvalidTokenError:
        raise ServiceError('Invalid token. Please, log in again.')


def check_auth_token(token: str):
    """
    Проверка валидности токена.
    :param token: токен
    :return:
    """
    if not token:
        raise ServiceError('Please, log in')

    payload = decode_auth_token(settings.SECRET_KEY, token)

    check_redis = redis.redis.get(token)
    if check_redis:
        raise ServiceError('This token is not valid anymore. Please, log in again.')

    return {'user': payload.get('user'),
            'logged_in': payload.get('logged_in'),
            'permissions': payload.get('permissions')}


def check_user_permissions(token: str, required_permission: list = None):
    if not token:
        return check_anonymous_permissions(required_permission)
    session_data = check_auth_token(token)
    if not session_data.get('permissions'):
        raise ServiceError('No user permissions specified')

    if not required_permission:
        raise ServiceError('No required permissions specified')

    if not set(required_permission).issubset(session_data.get('permissions')) \
            and 'full' not in session_data.get('permissions'):
        raise ServiceError('Permission denied')
    return session_data


def check_anonymous_permissions(required_permission):
    if not set(required_permission).issubset(['basic']):
        raise ServiceError('Permission denied')
    return {'user': 'anonymous', 'permissions': ['basic']}


def check_auth_decorator(method):
    @wraps(method)
    def check_():
        token = request.headers.get('Authorization')

        try:
            check_token = check_auth_token(token)
            return method(token_data=check_token)
        except ServiceError as e:
            return {'error': e.msg, 'result': None}

    return check_


def check_permissions_decorator(auth_permissions=None):
    def main_decorator(method):
        @wraps(method)
        def check_():
            token = request.headers.get('Authorization')
            req = request.get_json()
            required_permissions = auth_permissions
            if not required_permissions:
                if req:
                    required_permissions = req.get('required_permissions')
                else:
                    return {'error': "Permissions not specified", 'result': None}
            try:
                token_data = check_user_permissions(token, required_permissions)
                return method(token_data=token_data)
            except ServiceError as e:
                return {'error': e.msg, 'result': None}

        return check_
    return main_decorator
