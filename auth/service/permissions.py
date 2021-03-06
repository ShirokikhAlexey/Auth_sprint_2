from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError

from db.models import Permission, Role, RolePermission
from common.errors import ServiceError


def create_permission(session: SQLAlchemy().session, permission_name: str):
    """
    Добавление нового типа доступа
    :param session: сессия подключения к БД
    :param permission_name: тип доступа
    :return:
    """

    check_permission = (
        session.query(Permission)
        .filter(Permission.name == permission_name)
        .all()
    )
    if check_permission:
        raise ServiceError('This permission name is already used. Please, choose another one.')

    permission = Permission(name=permission_name)
    session.add(permission)
    session.commit()
    return 'You successfully created new permission'


def add_permission_to_role(session: SQLAlchemy().session, permission_name: str, role_name: str):
    """
    Добавление нового типа доступа для роли
    :param session: сессия подключения к БД
    :param permission_name: тип доступа
    :param role_name: название роли
    :return:
    """

    get_permission = (
        session.query(Permission)
        .filter(Permission.name == permission_name)
        .one_or_none()
    )
    if not get_permission:
        raise ServiceError('Permission not found')

    get_role = (
        session.query(Role)
        .filter(Role.name == role_name)
        .one_or_none()
    )
    if not get_role:
        raise ServiceError('Role not found')

    try:
        session.add(RolePermission(role_id=get_role.id, permission_id=get_permission.id))
        session.commit()
    except SQLAlchemyError:
        raise ServiceError('Role already has this permission')
    return 'You successfully added permission to role'
