from db.db import db
from db.models import Device
from db.partition import create_new_users_sign_in


def create_tables():
    db.create_all()
    session = db.session
    session.commit()

    device = Device(name='web')
    session.add(device)
    session.commit()

    create_new_users_sign_in(session, device.name, device.id)
