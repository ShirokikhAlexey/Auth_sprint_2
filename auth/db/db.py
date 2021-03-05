from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from common.settings import PG_PORT, PG_HOST, PG_PASSWD, PG_USER, DBNAME

db = SQLAlchemy()


def init_db(app: Flask):
    """
    Подключение к БД
    :param app:
    :return:
    """
    app.config['SQLALCHEMY_DATABASE_URI'] = \
        f'postgresql://{PG_USER}:{PG_PASSWD}@{PG_HOST}:{PG_PORT}/{DBNAME}'
    db.init_app(app)
