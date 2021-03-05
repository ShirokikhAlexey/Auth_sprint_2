from abc import ABCMeta, abstractmethod


# Абстрактный класс для работы с базой данных только на получение
class Database(metaclass=ABCMeta):
    # Открыть соединение с базой
    @abstractmethod
    def connect(self):
        pass

    # Закрыть соединение с базой
    @abstractmethod
    def close_connection(self):
        pass

    # Получение даннх
    @abstractmethod
    def get(self, **params):
        pass


# Абстрактный класс для работы с базой данных на получение и запись
class DatabaseGETSET(Database):
    # Запись данных
    @abstractmethod
    def set(self, **params):
        pass
