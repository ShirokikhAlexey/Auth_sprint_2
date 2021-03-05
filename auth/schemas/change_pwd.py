from marshmallow import Schema, fields

from common.utils import validate_passwd


class NewPassword(Schema):
    new_password = fields.Str(validate=validate_passwd, required=True)



