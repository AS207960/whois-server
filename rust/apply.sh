#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

sed -e "s/(version)/$VERSION/g" < kube.yaml | kubectl apply -f - || exit
