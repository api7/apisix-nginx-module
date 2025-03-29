#!/usr/bin/env bash

set -ex

CGO_ENABLED=0 go build -o grpc-web-server server.go

./grpc-web-server > grpc-web-server.log 2>&1 || (cat grpc-web-server.log && exit 1)&
