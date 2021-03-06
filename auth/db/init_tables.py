import bcrypt

from db.db import db
from db.models import Device, Role, Permission, UserRole, RolePermission, User
from db.partition import create_new_users_sign_in
from common import settings


def create_tables():
    db.create_all()
    session = db.session
    session.commit()

    device = Device(name='web')
    session.add(device)

    admin = User(
        login=settings.TEST_ADMIN_LOGIN,
        password=bcrypt.hashpw(bytes(settings.TEST_ADMIN_PWD, 'utf-8'), bcrypt.gensalt()).decode('utf-8'),
        email=settings.TEST_ADMIN_EMAIL,
        confirmed=True
    )
    session.add(admin)

    super_role = Role(name='super_user')
    session.add(super_role)
    super_wrights = Permission(name='full')
    session.add(super_wrights)
    session.flush()
    session.add(UserRole(user_id=admin.id, role_id=super_role.id))
    session.add(RolePermission(permission_id=super_wrights.id, role_id=super_role.id))

    common_role = Role(name='authorized')
    session.add(common_role)
    common_wrights = Permission(name='authorized')
    session.add(common_wrights)
    session.flush()
    session.add(RolePermission(permission_id=common_wrights.id, role_id=common_role.id))

    basic_role = Role(name='anonymous')
    session.add(basic_role)
    basic_wrights = Permission(name='basic')
    session.add(basic_wrights)
    session.flush()
    session.add(RolePermission(permission_id=basic_wrights.id, role_id=basic_role.id))
    session.add(RolePermission(permission_id=basic_wrights.id, role_id=common_role.id))

    session.commit()

    create_new_users_sign_in(session, device.name, device.id)
