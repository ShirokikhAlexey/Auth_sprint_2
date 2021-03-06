from marshmallow import Schema, fields, validate,  validates_schema, ValidationError

from common.utils import validate_passwd


class SignUpSchema(Schema):
    password = fields.Str(validate=validate_passwd, required=True)
    email = fields.Email(required=True)
    login = fields.Str(validate=validate.Length(min=5), required=True)
    roles = fields.List(fields.String, default=['authorized'])

    @validates_schema
    def validate_role(self, data, **kwargs):
        if data.get('roles') and 'super_user' in data.get('roles'):
            raise ValidationError('You can`t create super user with this method')
