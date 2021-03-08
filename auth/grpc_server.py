from concurrent import futures

import grpc
from flask import url_for, redirect

from db.db import db
from service.sign_up import sign_up_user
from service.log_in import log_in_user
from service.auth import check_user_permissions
from service.change_pwd import change_pwd
from service.history import get_login_history
from service.change_login import change_login
from service.permissions import create_permission, add_permission_to_role
from service.roles import change_user_roles, create_role
from common.errors import ServiceError
from grpc_.auth_pb2 import AddPermissionReply, AddRoleReply, AddPermissionRoleReply, NewLoginReply, \
    NewPasswordReply, ChangeUserRolesReply, CreateSUReply, HistoryReply, LoginReply, SignUpReply, MainPageReply
from grpc_.auth_pb2_grpc import AuthServicer, add_AuthServicer_to_server
from main import app, mail


class AuthGRPCService(AuthServicer):
    def AddPermission(self, request, context):
        with app.app_context():
            session = db.session
            try:
                data = check_user_permissions(request.auth_token, ['full'])
                create_permission(session, request.permission_name)
            except ServiceError as e:
                return AddPermissionReply(error=e.msg, result=None)
            return AddPermissionReply(error=None, result='New permission successfully created.')

    def AddRole(self, request, context):
        with app.app_context():
            session = db.session
            try:
                data = check_user_permissions(request.auth_token, ['full'])
                create_role(session, request.role_name)
            except ServiceError as e:
                return AddRoleReply(error=e.msg, result=None)
            return AddRoleReply(error=None, result='New role successfully created.')

    def AddPermissionRole(self, request, context):
        with app.app_context():
            session = db.session
            try:
                data = check_user_permissions(request.auth_token, ['full'])
                add_permission_to_role(session, request.permission_name, request.role_name)
            except ServiceError as e:
                return AddPermissionRoleReply(error=e.msg, result=None)
            return AddPermissionRoleReply(error=None, result='New role successfully created.')

    def NewLogin(self, request, context):
        with app.app_context():
            session = db.session
            try:
                data = check_user_permissions(request.auth_token, request.permission_name)
            except ServiceError as e:
                return NewLoginReply(error=e.msg, result=None)
            try:
                change = change_login(session, data.get('user'), request.new_login)
            except ServiceError as e:
                return NewLoginReply(error=e.msg, result=None)

            return NewLoginReply(error= None, result=change)

    def NewPassword(self, request, context):
        with app.app_context():
            session = db.session
            try:
                data = check_user_permissions(request.auth_token, ['authorized'])
                change = change_pwd(session, data.get('user'), request.new_password)
            except ServiceError as e:
                return NewPasswordReply(error=e.msg, result=None)
            return NewPasswordReply(error= None, result=data)

    def ChangeUserRoles(self, request, context):
        with app.app_context():
            session = db.session
            try:
                data = check_user_permissions(request.auth_token, ['full'])
                change_user_roles(session, request.user_id, request.new_roles)
            except ServiceError as e:
                return ChangeUserRolesReply(error=e.msg, result=None)
            return ChangeUserRolesReply(error=None, result="You successfully changed user roles.")

    def CreateSURequest(self, request, context):
        with app.app_context():
            session = db.session
            try:
                data = check_user_permissions(request.auth_token, ['full'])
                req = {
                    'password': request.password,
                    'email': request.email,
                    'login': request.login,
                    'roles': ['super_user']
                }
                sign_up_user(mail, session, req)
            except ServiceError as e:
                return CreateSUReply(error=e.msg, result=None)
            return CreateSUReply(error=None, result="Account successfully created. Please, confirm your email.")

    def History(self, request, context):
        with app.app_context():
            session = db.session
            try:
                data = check_user_permissions(request.auth_token, ['full'])
                user_history = get_login_history(session, data.get('user'),
                                                 request.date_start, request.date_end)
            except ServiceError as e:
                return HistoryReply(error=e.msg, result=None)
            return HistoryReply(error=None, result=user_history)

    def Login(self, request, context):
        with app.app_context():
            session = db.session
            try:
                data = check_user_permissions(request.auth_token)
            except ServiceError as e:
                return LoginReply(error=e.msg, result=None)

            if request.oauth:
                return redirect(
                    url_for('oauth_sign_up', provider=request.oauth, device=request.device, _external=True))

            req = {
                "password": request.password,
                "device": request.device,
                "email": request.email,
                "login": request.login,
                "recaptcha": request.recaptcha
            }
            try:
                gen_token = log_in_user(session, req, req.get('device', 'web'))
            except ServiceError as e:
                return LoginReply(error=e.msg, result=None)

            return LoginReply(error=None, result=gen_token)

    def SignUp(self, request, context):
        with app.app_context():
            session = db.session
            try:
                data = check_user_permissions(request.auth_token)
            except ServiceError as e:
                return SignUpReply(error=e.msg, result=None)

            if request.oauth:
                return redirect(
                    url_for('oauth_sign_up', provider=request.oauth, device=request.device, _external=True))

            req = {
                "password": request.password,
                "device": request.device,
                "email": request.email,
                "login": request.login,
                "recaptcha": request.recaptcha
            }
            try:
                gen_token = log_in_user(session, req, req.get('device', 'web'))
            except ServiceError as e:
                return SignUpReply(error=e.msg, result=None)

            return SignUpReply(error=None, result=gen_token)

    def MainPage(self, request, context):
        with app.app_context():
            try:
                data = check_user_permissions(request.auth_token)
            except ServiceError as e:
                return MainPageReply(error=e.msg, result=None)

            return MainPageReply(error=None, result=data)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_AuthServicer_to_server(
      AuthGRPCService(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print('GRPC started')
    server.wait_for_termination()
    print('GRPC stopped')


if __name__=='__main__':
    serve()