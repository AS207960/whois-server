#!/usr/bin/env bash

sed -e "s/(version)/$VERSION/g" < django.yaml | kubectl apply -f - || exit
#kubectl apply -f nginx.yaml || exit
