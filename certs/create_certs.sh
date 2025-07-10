#!/usr/bin/env bash

# Create directories for CA and certificates
mkdir -p ca/private ca/newcerts
touch ca/index.txt
echo 1000 > ca/serial

# Create CA configuration file
cat > ca/openssl.cnf << EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ./ca
certs             = \$dir/certs
crl_dir           = \$dir/crl
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/cacert.pem
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl.pem
private_key       = \$dir/private/cakey.pem
RANDFILE          = \$dir/private/.rand
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 365
default_crl_days  = 30
default_md        = sha256
preserve          = no
policy            = policy_match

[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits            = 2048
default_md              = sha256
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
attributes              = req_attributes
x509_extensions         = v3_ca
string_mask             = utf8only

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = US
stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = California
localityName                    = Locality Name (eg, city)
localityName_default            = San Francisco
organizationName                = Organization Name (eg, company)
organizationName_default        = Assignment3 CA
organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default  = Security
commonName                      = Common Name (e.g. server FQDN or YOUR name)
commonName_max                  = 64
emailAddress                    = Email Address
emailAddress_max                = 64

[ req_attributes ]
challengePassword               = A challenge password
challengePassword_min           = 4
challengePassword_max           = 20
unstructuredName                = An optional company name

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_server ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = 192.168.229.5
IP.3 = 192.168.56.6
EOF

# Create CA key and certificate
openssl genrsa -out ca/private/cakey.pem 2048
openssl req -new -x509 -days 3650 -key ca/private/cakey.pem -out ca/cacert.pem -config ca/openssl.cnf -subj "/C=US/ST=California/L=San Francisco/O=Assignment3 CA/OU=Security/CN=Assignment3 Root CA"

# Create HTTPS server key and certificate
openssl genrsa -out https_server.key 2048
openssl req -new -key https_server.key -out https_server.csr -config ca/openssl.cnf -subj "/C=US/ST=California/L=San Francisco/O=Assignment3/OU=HTTPS Server/CN=192.168.56.6"
openssl ca -batch -config ca/openssl.cnf -extensions v3_server -notext -in https_server.csr -out https_server.crt

# Create reverse proxy key and certificate
openssl genrsa -out reverse_proxy.key 2048
openssl req -new -key reverse_proxy.key -out reverse_proxy.csr -config ca/openssl.cnf -subj "/C=US/ST=California/L=San Francisco/O=Assignment3/OU=Reverse Proxy/CN=192.168.229.5"
openssl ca -batch -config ca/openssl.cnf -extensions v3_server -notext -in reverse_proxy.csr -out reverse_proxy.crt

echo "Certificates created successfully!"
