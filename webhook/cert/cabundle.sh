#!/bin/bash

cat ./cacert.pem | base64 | tr -d '\n'