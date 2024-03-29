# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import grpc_.auth_pb2 as auth__pb2


class AuthStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.AddPermission = channel.unary_unary(
                '/auth.Auth/AddPermission',
                request_serializer=auth__pb2.AddPermissionRequest.SerializeToString,
                response_deserializer=auth__pb2.AddPermissionReply.FromString,
                )
        self.AddRole = channel.unary_unary(
                '/auth.Auth/AddRole',
                request_serializer=auth__pb2.AddRoleRequest.SerializeToString,
                response_deserializer=auth__pb2.AddRoleReply.FromString,
                )
        self.AddPermissionRole = channel.unary_unary(
                '/auth.Auth/AddPermissionRole',
                request_serializer=auth__pb2.AddPermissionRoleRequest.SerializeToString,
                response_deserializer=auth__pb2.AddPermissionRoleReply.FromString,
                )
        self.NewLogin = channel.unary_unary(
                '/auth.Auth/NewLogin',
                request_serializer=auth__pb2.NewLoginRequest.SerializeToString,
                response_deserializer=auth__pb2.NewLoginReply.FromString,
                )
        self.NewPassword = channel.unary_unary(
                '/auth.Auth/NewPassword',
                request_serializer=auth__pb2.NewPasswordRequest.SerializeToString,
                response_deserializer=auth__pb2.NewPasswordReply.FromString,
                )
        self.ChangeUserRoles = channel.unary_unary(
                '/auth.Auth/ChangeUserRoles',
                request_serializer=auth__pb2.ChangeUserRolesRequest.SerializeToString,
                response_deserializer=auth__pb2.ChangeUserRolesReply.FromString,
                )
        self.CreateSU = channel.unary_unary(
                '/auth.Auth/CreateSU',
                request_serializer=auth__pb2.CreateSURequest.SerializeToString,
                response_deserializer=auth__pb2.CreateSUReply.FromString,
                )
        self.History = channel.unary_unary(
                '/auth.Auth/History',
                request_serializer=auth__pb2.HistoryRequest.SerializeToString,
                response_deserializer=auth__pb2.HistoryReply.FromString,
                )
        self.Login = channel.unary_unary(
                '/auth.Auth/Login',
                request_serializer=auth__pb2.LoginRequest.SerializeToString,
                response_deserializer=auth__pb2.LoginReply.FromString,
                )
        self.SignUp = channel.unary_unary(
                '/auth.Auth/SignUp',
                request_serializer=auth__pb2.SignUpRequest.SerializeToString,
                response_deserializer=auth__pb2.SignUpReply.FromString,
                )
        self.MainPage = channel.unary_unary(
                '/auth.Auth/MainPage',
                request_serializer=auth__pb2.MainPageRequest.SerializeToString,
                response_deserializer=auth__pb2.MainPageReply.FromString,
                )


class AuthServicer(object):
    """Missing associated documentation comment in .proto file."""

    def AddPermission(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def AddRole(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def AddPermissionRole(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def NewLogin(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def NewPassword(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ChangeUserRoles(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def CreateSU(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def History(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Login(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SignUp(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def MainPage(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_AuthServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'AddPermission': grpc.unary_unary_rpc_method_handler(
                    servicer.AddPermission,
                    request_deserializer=auth__pb2.AddPermissionRequest.FromString,
                    response_serializer=auth__pb2.AddPermissionReply.SerializeToString,
            ),
            'AddRole': grpc.unary_unary_rpc_method_handler(
                    servicer.AddRole,
                    request_deserializer=auth__pb2.AddRoleRequest.FromString,
                    response_serializer=auth__pb2.AddRoleReply.SerializeToString,
            ),
            'AddPermissionRole': grpc.unary_unary_rpc_method_handler(
                    servicer.AddPermissionRole,
                    request_deserializer=auth__pb2.AddPermissionRoleRequest.FromString,
                    response_serializer=auth__pb2.AddPermissionRoleReply.SerializeToString,
            ),
            'NewLogin': grpc.unary_unary_rpc_method_handler(
                    servicer.NewLogin,
                    request_deserializer=auth__pb2.NewLoginRequest.FromString,
                    response_serializer=auth__pb2.NewLoginReply.SerializeToString,
            ),
            'NewPassword': grpc.unary_unary_rpc_method_handler(
                    servicer.NewPassword,
                    request_deserializer=auth__pb2.NewPasswordRequest.FromString,
                    response_serializer=auth__pb2.NewPasswordReply.SerializeToString,
            ),
            'ChangeUserRoles': grpc.unary_unary_rpc_method_handler(
                    servicer.ChangeUserRoles,
                    request_deserializer=auth__pb2.ChangeUserRolesRequest.FromString,
                    response_serializer=auth__pb2.ChangeUserRolesReply.SerializeToString,
            ),
            'CreateSU': grpc.unary_unary_rpc_method_handler(
                    servicer.CreateSU,
                    request_deserializer=auth__pb2.CreateSURequest.FromString,
                    response_serializer=auth__pb2.CreateSUReply.SerializeToString,
            ),
            'History': grpc.unary_unary_rpc_method_handler(
                    servicer.History,
                    request_deserializer=auth__pb2.HistoryRequest.FromString,
                    response_serializer=auth__pb2.HistoryReply.SerializeToString,
            ),
            'Login': grpc.unary_unary_rpc_method_handler(
                    servicer.Login,
                    request_deserializer=auth__pb2.LoginRequest.FromString,
                    response_serializer=auth__pb2.LoginReply.SerializeToString,
            ),
            'SignUp': grpc.unary_unary_rpc_method_handler(
                    servicer.SignUp,
                    request_deserializer=auth__pb2.SignUpRequest.FromString,
                    response_serializer=auth__pb2.SignUpReply.SerializeToString,
            ),
            'MainPage': grpc.unary_unary_rpc_method_handler(
                    servicer.MainPage,
                    request_deserializer=auth__pb2.MainPageRequest.FromString,
                    response_serializer=auth__pb2.MainPageReply.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'auth.Auth', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class Auth(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def AddPermission(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/AddPermission',
            auth__pb2.AddPermissionRequest.SerializeToString,
            auth__pb2.AddPermissionReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def AddRole(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/AddRole',
            auth__pb2.AddRoleRequest.SerializeToString,
            auth__pb2.AddRoleReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def AddPermissionRole(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/AddPermissionRole',
            auth__pb2.AddPermissionRoleRequest.SerializeToString,
            auth__pb2.AddPermissionRoleReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def NewLogin(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/NewLogin',
            auth__pb2.NewLoginRequest.SerializeToString,
            auth__pb2.NewLoginReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def NewPassword(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/NewPassword',
            auth__pb2.NewPasswordRequest.SerializeToString,
            auth__pb2.NewPasswordReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def ChangeUserRoles(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/ChangeUserRoles',
            auth__pb2.ChangeUserRolesRequest.SerializeToString,
            auth__pb2.ChangeUserRolesReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def CreateSU(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/CreateSU',
            auth__pb2.CreateSURequest.SerializeToString,
            auth__pb2.CreateSUReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def History(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/History',
            auth__pb2.HistoryRequest.SerializeToString,
            auth__pb2.HistoryReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Login(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/Login',
            auth__pb2.LoginRequest.SerializeToString,
            auth__pb2.LoginReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def SignUp(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/SignUp',
            auth__pb2.SignUpRequest.SerializeToString,
            auth__pb2.SignUpReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def MainPage(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/auth.Auth/MainPage',
            auth__pb2.MainPageRequest.SerializeToString,
            auth__pb2.MainPageReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
