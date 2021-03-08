#!/bin/bash

set -e

pipenv run python main.py &
nohup pipenv run python grpc_server.py