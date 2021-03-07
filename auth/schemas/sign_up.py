from marshmallow import Schema, fields, validate,  validates_schema, ValidationError

from common.utils import validate_passwd


class SignUpSchema(Schema):
    password = fields.Str(validate=validate_passwd)
    email = fields.Email()
    login = fields.Str(validate=validate.Length(min=5))
    roles = fields.List(fields.String)
    oauth = fields.Str()
    device = fields.Str()

    @validates_schema
    def validate_role(self, data, **kwargs):
        if data.get('roles') and 'super_user' in data.get('roles'):
            raise ValidationError('You can`t create super user with this method')

    @validates_schema
    def validate_req_params(self, data, **kwargs):
        if not (data.get('oauth') and data.get('device')) and not (data.get('password')
                                                                   and data.get('email') and data.get('login')):
            raise ValidationError('Sign up with oauth or specify your password, login and email')
