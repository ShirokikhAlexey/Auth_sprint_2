from marshmallow import Schema, fields


class AddRoleSchema(Schema):
    role_name = fields.Str(required=True)
