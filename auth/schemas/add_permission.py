from marshmallow import Schema, fields


class AddPermissionSchema(Schema):
    permission_name = fields.Str(required=True)
