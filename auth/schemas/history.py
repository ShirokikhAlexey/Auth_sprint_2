from marshmallow import Schema, fields


class HistorySchema(Schema):
    date_start = fields.Date(required=True, format='%Y-%m-%d')
    date_end = fields.Date(required=True, format='%Y-%m-%d')
