from datetime import datetime

import bcrypt
from flask_sqlalchemy import SQLAlchemy

from db.models import User
from common.errors import ServiceError


def change_pwd(session: SQLAlchemy().session, user_id: str, new_password: str):
    """
    Смена пароля пользователя
    :param session: сессия подключения к БД
    :param user_id: id пользователя
    :param new_password: Новый пароль
    :return:
    """
    user = (
        session.query(User)
        .filter(User.id == user_id)
        .one_or_none()
    )
    if not user:
        raise ServiceError('User not found')

    user.password = bcrypt.hashpw(bytes(new_password, 'utf-8'), bcrypt.gensalt()).decode('utf-8'),
    user.updated_at = datetime.now()

    session.commit()
    return 'You successfully changed password'
