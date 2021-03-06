from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError

from db.models import Role, User, UserRole
from common.errors import ServiceError


def create_role(session: SQLAlchemy().session, role_name: str):
    """
    Добавление новой роли
    :param session: сессия подключения к БД
    :param role_name: название роли
    :return:
    """

    check_role = (
        session.query(Role)
        .filter(Role.name == role_name)
        .all()
    )
    if check_role:
        raise ServiceError('This role name is already used. Please, choose another one.')

    role = Role(name=role_name)
    session.add(role)
    session.commit()
    return 'You successfully created new role'


def change_user_roles(session: SQLAlchemy().session, user_id: str, new_roles: list):
    """
    Изменение списка ролей пользователя
    :param session: сессия подключения к БД
    :param user_id: id пользователя
    :param new_roles: новый список ролей
    :return:
    """

    check_user = (
        session.query(User)
        .filter(User.id == user_id)
        .one_or_none()
    )
    if not check_user:
        raise ServiceError('User not found')

    check_roles = (
        session.query(Role)
        .filter(Role.name.in_(new_roles))
        .all()
    )
    roles_ids = [role.id for role in check_roles]
    if len(new_roles) != len(roles_ids):
        raise ServiceError('Role not found')

    existing_roles = (
        session.query(UserRole)
        .filter(UserRole.user_id == user_id)
        .all()
    )
    existing_roles = [role.role_id for role in existing_roles]

    (
        session.query(UserRole)
        .filter(UserRole.user_id == user_id, UserRole.role_id.in_(roles_ids))
        .update({UserRole.active: True}, synchronize_session=False)
    )
    session.commit()
    (
        session.query(UserRole)
        .filter(UserRole.user_id == user_id, UserRole.role_id.notin_(roles_ids))
        .update({UserRole.active: False}, synchronize_session=False)
    )
    session.commit()
    
    for role in roles_ids:
        if role not in existing_roles:
            session.add(UserRole(user_id=user_id, role_id=role))
    session.commit()
    return 'You successfully updated user roles'
