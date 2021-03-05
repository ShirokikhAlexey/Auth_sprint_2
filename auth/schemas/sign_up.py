from marshmallow import Schema, fields, validate

from common.utils import validate_passwd


class SignUpSchema(Schema):
    password = fields.Str(validate=validate_passwd, required=True)
    email = fields.Email(required=True)
    login = fields.Str(validate=validate.Length(min=5), required=True)
