import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID

from db.db import db


class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {"schema": "content"}

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    login = db.Column(db.String, unique=True, nullable=False, index=True)
    password = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False, index=True)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=datetime.now())
    updated_at = db.Column(db.TIMESTAMP, default=None, onupdate=datetime.now())

    def __repr__(self):
        return f'<User {self.login}>'


class Device(db.Model):
    __tablename__ = 'device_type'
    __table_args__ = {"schema": "content"}

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    name = db.Column(db.String, unique=True, nullable=False, index=True)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=datetime.now())
    updated_at = db.Column(db.TIMESTAMP, default=None, onupdate=datetime.now())


class UsersSignIn(db.Model):
    __tablename__ = 'users_sign_in'
    __table_args__ = {"schema": "content", "postgresql_partition_by": "LIST (user_device_type_id)"}

    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('content.users.id'), primary_key=True, nullable=False)
    logined_by = db.Column(db.TIMESTAMP, nullable=False, default=datetime.now(), primary_key=True)
    user_agent = db.Column(db.String, default=None)
    user_device_type_id = db.Column(UUID(as_uuid=True), db.ForeignKey('content.device_type.id'),
                                    nullable=False, primary_key=True)


class Role(db.Model):
    __tablename__ = 'roles'
    __table_args__ = {"schema": "content"}
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    name = db.Column(db.String, unique=True, nullable=False, index=True)
    decr = db.Column(db.String, nullable=True)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=datetime.now())
    updated_at = db.Column(db.TIMESTAMP, default=None, onupdate=datetime.now())


class UserRole(db.Model):
    __tablename__ = 'user_role'
    __table_args__ = {"schema": "content"}

    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('content.users.id'), primary_key=True, nullable=False)
    role_id = db.Column(UUID(as_uuid=True), db.ForeignKey('content.roles.id'), primary_key=True, nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=datetime.now())
    updated_at = db.Column(db.TIMESTAMP, default=None, onupdate=datetime.now())


class Permission(db.Model):
    __tablename__ = 'permissions'
    __table_args__ = {"schema": "content"}
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    name = db.Column(db.String, unique=True, nullable=False, index=True)
    decr = db.Column(db.String, nullable=True)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=datetime.now())
    updated_at = db.Column(db.TIMESTAMP, default=None, onupdate=datetime.now())


class RolePermission(db.Model):
    __tablename__ = 'role_permission'
    __table_args__ = {"schema": "content"}

    permission_id = db.Column(UUID(as_uuid=True), db.ForeignKey('content.permissions.id'),
                              primary_key=True, nullable=False)
    role_id = db.Column(UUID(as_uuid=True), db.ForeignKey('content.roles.id'), primary_key=True, nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=datetime.now())
    updated_at = db.Column(db.TIMESTAMP, default=None, onupdate=datetime.now())