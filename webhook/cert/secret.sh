#!/bin/bash
# create the secret with CA cert and server cert/key
kubectl delete secret webhook-wsh-cert
kubectl create secret generic webhook-wsh-cert \
        --from-file=key.pem=./cakey.pem \
        --from-file=cert.pem=./cacert.pem \
        -o yaml |
    kubectl -n default apply -f -

