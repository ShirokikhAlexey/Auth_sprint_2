from marshmallow import Schema, fields


class AddPermissionRoleSchema(Schema):
    permission_name = fields.Str(required=True)
    role_name = fields.Str(required=True)
