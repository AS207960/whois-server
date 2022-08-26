#!/usr/bin/env bash

python3 -m grpc_tools.protoc --python_out=whois/rdap_grpc --grpc_python_out=whois/rdap_grpc -I ../rust/proto/  ../rust/proto/rdap.proto
