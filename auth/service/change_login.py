from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

from db.models import User
from common.errors import ServiceError


def change_login(session: SQLAlchemy().session, user_id: str, new_login: str):
    """
    Смена логина пользователя
    :param session: сессия подключения к БД
    :param user_id: id пользователя
    :param new_login: Новый пароль
    :return:
    """

    check_login = (
        session.query(User)
        .filter(User.login == new_login)
        .all()
    )
    if check_login:
        raise ServiceError('This login is already used. Please, choose another one.')

    user = (
        session.query(User)
        .filter(User.id == user_id)
        .one_or_none()
    )
    if not user:
        raise ServiceError('User not found')

    user.login = new_login,
    user.updated_at = datetime.now()

    session.commit()
    return 'You successfully changed login'
