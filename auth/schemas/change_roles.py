from marshmallow import Schema, fields


class ChangeUserRolesSchema(Schema):
    user_id = fields.Str(required=True)
    new_roles = fields.List(fields.String, required=True)
