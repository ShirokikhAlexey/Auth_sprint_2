from flask_mail import Message, Mail


def send_email(mail_app: Mail, to: str, subject: str, template, sender: str = None):
    """
    Отправка сообщений
    :param mail_app:
    :param to: получатель
    :param subject: тема сообщения
    :param template: страница сообщения
    :param sender: отправитель
    :return:
    """
    msg = Message(
        subject,
        recipients=[to],
        html=template
    )
    if sender:
        msg.sender = sender
    mail_app.send(msg)
