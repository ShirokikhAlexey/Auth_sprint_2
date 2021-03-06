import requests

from datetime import datetime, timedelta
from uuid import uuid4

import bcrypt
import jwt
from flask_sqlalchemy import SQLAlchemy

from db.models import User, Device, UsersSignIn, Permission, Role, RolePermission, UserRole
from common import settings
from common.errors import ServiceError


def log_in_user(session: SQLAlchemy().session, user_data: dict, device: str = 'web'):
    """
    Авторизация пользователя. Генерация токена
    :param session: подключение к бд
    :param user_data: данные пользователя (логин, пароль, email)
    :param device: тип устройства, с которого осуществляется вход
    :return:
    """
    if not user_data.get('login') and not user_data.get('email'):
        raise ServiceError('Specify your login or email')

    check_captcha(user_data.get('recaptcha'))

    user = check_password(session, user_data.get('login'), user_data.get('email'), user_data.get('password'))

    get_device = get_device_by_name(session, device)

    log_in_time = datetime.now()

    permissions = get_user_permissions(session, user.id)

    gen_token = encode_auth_token(settings.SECRET_KEY, user.id, permissions, log_in_time,
                                  settings.TOKEN_EXPIRE_TIME_HOURS,
                                  settings.TOKEN_EXPIRE_TIME_MINUTES)

    user_session = UsersSignIn(user_id=user.id, logined_by=log_in_time,
                               user_device_type_id=get_device.id)
    session.add(user_session)
    session.commit()

    return gen_token


def check_password(session: SQLAlchemy().session, login: str, email: str, password: str):
    """
    Проверка корректности введенного при авторизации пароля
    :param session: подключение к бд
    :param login: логин (необязателен, если указан email)
    :param email: email (необязателен, если указан логин)
    :param password: пароль
    :return:
    """
    user = (
        session.query(User)
    )
    if login:
        user = user.filter(User.login == login)

    if email:
        user = user.filter(User.email == email)

    user = user.one_or_none()

    if not user:
        raise ServiceError('User not found')

    if not user.confirmed:
        raise ServiceError('Please, confirm your email.')

    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        raise ServiceError('Incorrect password')

    return user


def encode_auth_token(key: str, user_id: uuid4, permissions: list, log_in_time: datetime, hours: int = 0, minutes: int = 2):
    """
    Генерация токена авторизации
    :param key: секретный ключ
    :param user_id: id пользователя
    :param log_in_time: время входа
    :param hours: время действия токена (часы)
    :param minutes: ремя действия токена (минуты)
    :return:
    """
    try:
        payload = {
            'exp': (log_in_time + timedelta(days=0, hours=hours, minutes=minutes)).timestamp(),
            'logged_in': log_in_time.timestamp(),
            'user': str(user_id),
            'permissions': permissions
        }
        return jwt.encode(
            payload,
            key,
            algorithm='HS256'
        ).decode('utf-8')
    except Exception as e:
        raise ServiceError(str(e))


def get_device_by_name(session: SQLAlchemy().session, name: str = 'web'):
    """
    Получение типа устройства по названию
    :param session: подключение к бд
    :param name: тип устройства
    :return:
    """
    device = (
        session.query(Device)
        .filter(Device.name == name)
        .one_or_none()
    )
    if not device:
        raise ServiceError('Device not found')

    return device


def check_captcha(captcha_response: str):
    """
    Проверка корректности токена recaptcha
    :param captcha_response: токен recaptcha
    :return:
    """
    data = {
        'secret': settings.RECAPTCHA_PRIVATE_KEY,
        'response': captcha_response
    }
    check = requests.post(settings.RECAPTCHA_VERIFY_URL, data)
    if not check.json().get('success'):
        raise ServiceError('Invalid recaptcha token')


def get_user_permissions(session, user_id: str):
    permissions = (
        session.query(Permission.name)
        .select_from(Permission)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(UserRole.user_id == user_id)
        .all()
    )
    if not permissions:
        raise ServiceError('User permissions not found')

    return [permission.name for permission in permissions]