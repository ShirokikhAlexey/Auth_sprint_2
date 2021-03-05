from db.db_base import DatabaseGETSET
from redis import Redis


# Класс для работы с базой Redis
class RedisBase(DatabaseGETSET):
    def __init__(self, host: str, port: str, db_number: int):
        self.host = host
        self.port = port
        self.db_number = db_number
        self.connection = None

    # Отрыть соединение с базой
    def connect(self):
        self.connection = Redis(host=self.host, port=self.port, db=self.db_number)

    # Закрыть соединение с базой
    def close_connection(self):
        self.connection.close()

    def get(self, key: str):
        """
        Получить запись по ключу
        :param key: ключ записи в схеме
        :return:
        """
        return self.connection.get(key)

    def set(self, key: str, value: dict, expire: int):
        """
        Поиск данных в БД
        :param key: ключ записи в БД
        :param value: значение
        :param expire: время кэширования
        :return:
        """
        return self.connection.set(key, value, ex=expire)


redis: RedisBase = None
