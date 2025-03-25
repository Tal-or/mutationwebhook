#!/usr/bin/env bash

set -e

WORKSPACE_DIR="tls"

openssl x509 -req -in ${WORKSPACE_DIR}/tls.csr -signkey ${WORKSPACE_DIR}/tls.key -extfile tls/v3.ext -days 365 -sha256 \
  -out ${WORKSPACE_DIR}/tls.crt

printf "your certificate Common Name (CN) is:"
openssl x509 -in tls/tls.crt -noout -subject

printf "your base64 tls.key is:\n"
cat ${WORKSPACE_DIR}/tls.key | base64 -w0

printf "\nyour base64 tls.crt is:\n"
cat ${WORKSPACE_DIR}/tls.crt | base64 -w0
printf "\n"

oc create secret tls resource-to-claim-mutating-webhook-secret -n nrt-to-dra --cert=${WORKSPACE_DIR}/tls.crt --key=${WORKSPACE_DIR}/tls.key
