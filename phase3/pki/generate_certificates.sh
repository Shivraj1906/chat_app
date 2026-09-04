#!/bin/sh
set -e

# Usage: ./generate_certificates.sh [directory] [server-ip]
DIR=${1:-pki}
IP=${2:-127.0.0.1}
mkdir -p "$DIR"

openssl genrsa -out "$DIR/ca.key" 3072
openssl req -x509 -new -key "$DIR/ca.key" -days 3650 \
  -out "$DIR/ca.crt" -subj "/CN=Chat App CA"

openssl genrsa -out "$DIR/server.key" 3072
openssl req -new -key "$DIR/server.key" -out "$DIR/server.csr" \
  -subj "/CN=$IP" -addext "subjectAltName=IP:$IP"
openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca.crt" \
  -CAkey "$DIR/ca.key" -CAcreateserial -copy_extensions copy \
  -days 825 -out "$DIR/server.crt"

rm "$DIR/server.csr" "$DIR/ca.srl"
chmod 600 "$DIR/ca.key" "$DIR/server.key"
echo "Certificates written to $DIR"
