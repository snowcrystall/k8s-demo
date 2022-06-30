#!/bin/bash

openssl genrsa -out cakey.pem 2048
openssl req -new -x509 -addext "subjectAltName = DNS:webhook-svc.default.svc" -subj "/C=CN/ST=GD/L=SZ/O=vihoo/OU=dev/CN=webhook-svc.default.svc/emailAddress=yy@vivo.com" -key cakey.pem -out cacert.pem