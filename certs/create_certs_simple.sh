#!/usr/bin/env sh

# Create directories for CA and certificates
mkdir -p ca/private ca/newcerts
touch ca/index.txt
echo 1000 > ca/serial

# Create CA key and certificate
openssl genrsa -out ca/private/cakey.pem 2048
openssl req -new -x509 -days 3650 -key ca/private/cakey.pem -out ca/cacert.pem -subj "/C=US/ST=California/L=San Francisco/O=Assignment3 CA/OU=Security/CN=Assignment3 Root CA"

# Create HTTPS server key and certificate
openssl genrsa -out https_server.key 2048
openssl req -new -key https_server.key -out https_server.csr -subj "/C=US/ST=California/L=San Francisco/O=Assignment3/OU=HTTPS Server/CN=192.168.56.6"
openssl x509 -req -days 365 -in https_server.csr -CA ca/cacert.pem -CAkey ca/private/cakey.pem -CAcreateserial -out https_server.crt

# Create reverse proxy key and certificate
openssl genrsa -out reverse_proxy.key 2048
openssl req -new -key reverse_proxy.key -out reverse_proxy.csr -subj "/C=US/ST=California/L=San Francisco/O=Assignment3/OU=Reverse Proxy/CN=192.168.56.4"
openssl x509 -req -days 365 -in reverse_proxy.csr -CA ca/cacert.pem -CAkey ca/private/cakey.pem -CAcreateserial -out reverse_proxy.crt

echo "Certificates created successfully!"
