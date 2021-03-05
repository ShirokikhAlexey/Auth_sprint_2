from itsdangerous import URLSafeTimedSerializer
from flask import url_for, render_template
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy

from common import settings
from common.errors import ServiceError
from common.email import send_email
from db.models import User


# Время существования токена
exp_time = settings.TOKEN_EXPIRE_TIME_HOURS*3600 + settings.TOKEN_EXPIRE_TIME_MINUTES*60


def generate_email_confirmation_token(email: str):
    """
    Генерация токена подтверждения email
    :param email: email
    :return:
    """
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY)
    return serializer.dumps(email)


def check_email_token(token: str):
    """
    Проверка токена подтверждения email
    :param token: токен подтверждения
    :return:
    """
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY)
    try:
        email = serializer.loads(
            token,
            max_age=exp_time
        )
    except Exception as e:
        raise ServiceError("Invalid email confirmation token")
    return email


def send_confirmation_email(mail_app: Mail, email: str):
    """
    Отправка сообщения со ссылкой для подтверждения
    :param mail_app:
    :param email: email пользователя
    :return:
    """
    token = generate_email_confirmation_token(email)
    url = url_for('confirm_email_route', token=token, _external=True)
    html = render_template('confirm_email.html', confirm_url=url)
    subject = "Please confirm your email"
    send_email(mail_app, email, subject, html, sender=settings.DEFAULT_MAIL_SENDER)


def confirm_email(session: SQLAlchemy(), token: str):
    """
    Проверка токена и подтверждение пользователя в БД
    :param session: сессия работы с БД
    :param token: токен
    :return:
    """
    email = check_email_token(token)

    user = (
        session.query(User)
        .filter(User.email == email)
        .one_or_none()
    )
    if not user:
        raise ServiceError('User not found')

    if user.confirmed:
        raise ServiceError('User email already confirmed. Please, log in.')

    user.confirmed = True
    session.add(user)
    session.commit()
