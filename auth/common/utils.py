from marshmallow import ValidationError

import re


PASSWORD_PAT = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,20}$")


def validate_passwd(passwd: str):
    """
    Проверка валидности пароля
    :param passwd: Пароль
    :return:
    """
    if not PASSWORD_PAT.match(passwd):
        raise ValidationError('Password should be 8-20 characters long without spaces and should contain '
                              'at least one digit, '
                              'at least one uppercase letter, at least one lowercase letter, '
                              'at least one special character')
