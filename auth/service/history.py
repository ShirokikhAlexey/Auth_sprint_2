from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

from db.models import UsersSignIn, Device
from common.errors import ServiceError


def get_login_history(session: SQLAlchemy().session, user_id: str, date_start: str, date_end: str):
    """
    Получение истоиии входов пользователя
    :param session: сессия подключения к БД
    :param user_id: id пользователя
    :param date_start: нижняя граница даты в формате Y-m-d
    :param date_end: верхняя граница даты в формате Y-m-d
    :return:
    """

    history = (
        session.query(UsersSignIn.logined_by.label('login_time'), UsersSignIn.user_agent, Device.name.label('device'))
        .select_from(UsersSignIn)
        .join(Device, Device.id == UsersSignIn.user_device_type_id)
        .filter(
            UsersSignIn.user_id == user_id,
            UsersSignIn.logined_by >= datetime.strptime(date_start, '%Y-%m-%d'),
            UsersSignIn.logined_by < datetime.strptime(date_end, '%Y-%m-%d')
        )
        .all()
    )
    if not history:
        raise ServiceError('No results found')

    resp = []
    for time, agent, device in history:
        resp.append(
            {
                'login_time': time,
                'user_agent': agent,
                'device': device
            }
        )

    return resp
