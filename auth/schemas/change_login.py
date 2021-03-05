from marshmallow import Schema, fields, validate


class NewLogin(Schema):
    new_login = fields.Str(validate=validate.Length(min=5), required=True)



