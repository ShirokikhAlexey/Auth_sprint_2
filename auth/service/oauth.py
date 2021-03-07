import json
import random
import string
import re
from datetime import datetime

import bcrypt
from flask import url_for, redirect, request
from rauth import OAuth2Service

from common import settings
from db.models import User, UsersSignIn
from service.log_in import get_device_by_name, get_user_permissions, encode_auth_token
from service.sign_up import add_user_roles, check_roles


class OAuthSignIn(object):
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = settings.OAUTH_CREDENTIALS[provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']

    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name,
                       _external=True)

    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]


class VkSignIn(OAuthSignIn):
    def __init__(self):
        super(VkSignIn, self).__init__('vk')
        self.service = OAuth2Service(
            name='vk',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url=settings.VK_AUTHORIZE_URL,
            access_token_url=settings.VK_ACCESS_TOKEN_URL,
            base_url=settings.VK_BASE_URL
        )
        self.device = None

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='email',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        def decode_json(payload):
            return json.loads(payload.decode('utf-8'))

        if 'code' not in request.args:
            return None
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()},
            decoder=decode_json
        )
        me = oauth_session.get('me').json()
        return (
            me.get('email')
        )


def sign_up_oauth(session, email, device='web'):
    check_email = (
        session.query(User)
        .filter(User.email == email)
        .one_or_none()
    )
    if check_email:
        return log_in_oauth(session, check_email, device)

    login = gen_login(session)
    password = gen_pwd()
    user = User(login=login,
                password=bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt()).decode('utf-8'),
                email=email,
                confirmed=True
                )
    session.add(user)

    roles = ['authorized']
    add_user_roles(session, check_roles(session, roles), user.id)
    session.commit()

    return log_in_oauth(session, email, device)


def log_in_oauth(session, user, device='web'):
    get_device = get_device_by_name(session, device)

    log_in_time = datetime.now()

    permissions = get_user_permissions(session, user.id)

    gen_token = encode_auth_token(settings.SECRET_KEY, user.id, permissions, log_in_time,
                                  settings.TOKEN_EXPIRE_TIME_HOURS,
                                  settings.TOKEN_EXPIRE_TIME_MINUTES)

    user_session = UsersSignIn(user_id=user.id, logined_by=log_in_time,
                               user_device_type_id=get_device.id)
    session.add(user_session)
    session.commit()

    return gen_token


def gen_login(session):
    login = ''.join(random.choice(string.ascii_letters) for i in range(8))
    while check_login(session, login):
        login = ''.join(random.choice(string.ascii_letters) for i in range(8))
    return login


def check_login(session, login):
    check = (
        session.query(User)
        .filter(User.login == login)
        .one_or_none()
    )
    if check:
        return True
    return False


PASSWORD_PAT = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,20}$")


def gen_pwd():
    password_characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(password_characters) for i in range(8))
    while not re.match(PASSWORD_PAT, password):
        password = ''.join(random.choice(password_characters) for i in range(8))

    return password
