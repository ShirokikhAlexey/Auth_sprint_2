import os

DBNAME = os.getenv('DBNAME', 'users')
PG_USER = os.getenv('PG_USER', 'postgres')
PG_PASSWD = os.getenv('PG_PASSWD', 1234)
PG_PORT = os.getenv('PG_PORT', 5432)
PG_HOST = os.getenv('PG_HOST', "127.0.0.1")

REDIS_HOST = os.getenv('REDIS_HOST', "127.0.0.1")
REDIS_PORT = os.getenv('REDIS_PORT', 6379)
SESSION_REDIS_DB = int(os.getenv('SESSION_REDIS_DB', 0))
REDIS_EXPIRE_TIME = int(os.getenv('REDIS_EXPIRE_TIME', 43200))

SECRET_KEY = os.getenv('SECRET_KEY')


TOKEN_EXPIRE_TIME_HOURS = int(os.getenv('TOKEN_EXPIRE_TIME_HOURS', 0))
TOKEN_EXPIRE_TIME_MINUTES = int(os.getenv('TOKEN_EXPIRE_TIME_MINUTES', 2))

MAIL_SERVER = os.getenv('MAIL_SERVER', '127.0.0.1')
MAIL_PORT = int(os.getenv('MAIL_PORT', 25))
MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'test')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'test')

DEFAULT_MAIL_SENDER = os.getenv('DEFAULT_MAIL_SENDER')


RECAPTCHA_PUBLIC_KEY = os.getenv('RECAPTCHA_PUBLIC_KEY')
RECAPTCHA_PRIVATE_KEY = os.getenv('RECAPTCHA_PRIVATE_KEY')
RECAPTCHA_VERIFY_URL = os.getenv('RECAPTCHA_VERIFY_URL')

TEST_ADMIN_LOGIN = os.getenv('TEST_ADMIN_LOGIN')
TEST_ADMIN_PWD = os.getenv('TEST_ADMIN_PWD')
TEST_ADMIN_EMAIL = os.getenv('TEST_ADMIN_EMAIL')

TEST_USER_LOGIN = os.getenv('TEST_USER_LOGIN')
TEST_USER_PWD = os.getenv('TEST_USER_PWD')
TEST_USER_EMAIL = os.getenv('TEST_USER_EMAIL')

OAUTH_CREDENTIALS = {
    'vk': {
        "id": os.getenv('VK_ID'),
        "secret": os.getenv('VK_SECRET')
    }
}

VK_AUTHORIZE_URL = os.getenv('VK_AUTHORIZE_URL')
VK_ACCESS_TOKEN_URL = os.getenv('VK_ACCESS_TOKEN_URL')
VK_BASE_URL = os.getenv('VK_BASE_URL')