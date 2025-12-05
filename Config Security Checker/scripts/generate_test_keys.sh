#!/usr/bin/env bash
set -e
mkdir -p test_keys
# generate 1024-bit (weak) RSA
openssl genrsa -out test_keys/weak_rsa.pem 1024
# generate 4096-bit (strong) RSA
openssl genrsa -out test_keys/strong_rsa.pem 4096
echo "Generated test keys into test_keys/"
