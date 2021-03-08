#!/bin/bash

exec pipenv run python main.py &
exec pipenv run python grpc_/grpc_server.py