import bcrypt
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail

from db.models import User, Role, UserRole
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

    roles = user_data.get('roles') if user_data.get('roles') else ['authorized']
    add_user_roles(session, check_roles(session, roles), user.id)
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


def check_roles(session: SQLAlchemy(), roles: list):
    """
    Проверка существования ролей
    :param session: подключение к бд
    :param roles:  список ролей
    :return:
    """

    roles_db = (
        session.query(Role)
        .filter(Role.name.in_(roles))
        .all()
    )
    if len(roles_db) != len(roles):
        raise ServiceError('Role not found')

    return roles_db


def add_user_roles(session: SQLAlchemy(), roles: list, user_id: str):
    """
    Добавление ролей для пользователя
    :param session:
    :param roles:
    :param user_id:
    :return:
    """

    for role in roles:
        try:
            user_role = UserRole(user_id=user_id, role_id=role.id)
            session.add(user_role)
        except SQLAlchemyError:
            raise ServiceError(f'User already has the role {role.name}')

