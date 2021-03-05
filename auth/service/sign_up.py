import bcrypt
from sqlalchemy import or_
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail

from db.models import User
from common.errors import ServiceError
from service.confirm import send_confirmation_email


def sign_up_user(mail_app: Mail, session: SQLAlchemy().session, user_data: dict):
    """
    Регистрация нового пользователя
    :param mail_app:
    :param session: подключение к бд
    :param user_data: данные пользователя (логин, email, пароль)
    :return:
    """
    check_user(session, user_data.get('login'), user_data.get('email'))

    user = User(login=user_data.get('login'),
                password=bcrypt.hashpw(bytes(user_data.get('password'), 'utf-8'), bcrypt.gensalt()).decode('utf-8'),
                email=user_data.get('email'),
                confirmed=False
                )
    session.add(user)
    session.commit()
    send_confirmation_email(mail_app, user_data.get('email'))


def check_user(session: SQLAlchemy().session, login: str, email: str):
    """
    Проверка существования пользователя с заданными логином или email
    :param session: подключение к бд
    :param login: логин
    :param email: email
    :return:
    """
    check = (
        session.query(User)
        .filter(or_(User.login == login, User.email == email))
        .all()
    )
    if check:
        raise ServiceError('This login or email is already used. Please, try another one')
