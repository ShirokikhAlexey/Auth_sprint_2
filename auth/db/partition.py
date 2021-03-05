from flask_sqlalchemy import SQLAlchemy


def create_new_users_sign_in(session: SQLAlchemy().session, device_type: str, device_type_id: str):
    """
    Функция для создании новой таблицы в PARTITION content.users_sign_in
    :param session: сессия подключения к бд
    :param device_type: тип устройства
    :param device_type_id: id типа устройства
    :return:
    """
    sql = f"""
    CREATE TABLE content.users_sign_in_{device_type} PARTITION OF content.users_sign_in
    FOR VALUES IN ('{device_type_id}');
    CREATE UNIQUE INDEX sign_in_users_{device_type} ON 
    content.users_sign_in_{device_type} (user_id, logined_by);
    """

    session.execute(sql)
    session.commit()
