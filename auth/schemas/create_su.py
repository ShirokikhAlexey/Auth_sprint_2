from marshmallow import Schema, fields, validate, validates_schema, ValidationError

from common.utils import validate_passwd


class SUSchema(Schema):
    password = fields.Str(validate=validate_passwd, required=True)
    email = fields.Email(required=True)
    login = fields.Str(validate=validate.Length(min=5), required=True)
