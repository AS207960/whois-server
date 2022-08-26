#!/usr/bin/env bash

./venv/bin/python3 -m grpc_tools.protoc --python_out=whois/rdap_grpc --grpc_python_out=whois/rdap_grpc -I ../rust/proto/  ../rust/proto/rdap.proto
./venv/bin/python3 -m grpc_tools.protoc --python_out=whois/whois_grpc --grpc_python_out=whois/whois_grpc -I ../rust/proto/  ../rust/proto/whois.proto

find whois/rdap_grpc -maxdepth 1 -name \*.py -exec bash -c "FILE={}; sed -E \"/^from (google\.)|(\.)/! s/^import (.+_pb2)/from \. import \1/\" \$FILE > \$FILE.new; mv \$FILE.new \$FILE" \;
find whois/whois_grpc -maxdepth 1 -name \*.py -exec bash -c "FILE={}; sed -E \"/^from (google\.)|(\.)/! s/^import (.+_pb2)/from \. import \1/\" \$FILE > \$FILE.new; mv \$FILE.new \$FILE" \;
