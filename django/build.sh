#!/usr/bin/env bash

docker build -t "as207960/whois-django:$VERSION" . || exit
docker push "as207960/whois-django:$VERSION" || exit

