from marshmallow import Schema, fields, validates_schema, ValidationError, validate


class LoginSchema(Schema):
    password = fields.Str(required=True)
    device = fields.Str()
    email = fields.Email()
    login = fields.Str(validate=validate.Length(min=5))
    recaptcha = fields.Str(required=True)

    @validates_schema
    def validate_anyof(self, data, **kwargs):
        if 'login' not in data and 'email' not in data:
            raise ValidationError('Login or email should be specified')
