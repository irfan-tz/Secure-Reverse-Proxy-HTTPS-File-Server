# Secure Reverse Proxy for HTTPS File Server

This project implements a secure reverse proxy that interfaces with an HTTPS server running on port 443, acting as a file-sharing service. Clients connect to the reverse proxy over a TLS-encrypted connection, authenticate using PAM, and can perform file operations through a command-line interface.

## System Architecture

### 1. HTTPS Server (VM2 - FreeBSD)
- Nginx server running on port 443
- Serves files from `/var/www/files`
- Handles PUT requests in `/var/www/files/upload` directory
- TLS encryption using server certificates

### 2. Reverse Proxy (VM1 - GhostBSD)
- Runs on port 8443
- Authenticates users via PAM
- Forwards authenticated requests to HTTPS server
- Maintains secure TLS connections with both client and HTTPS server

### 3. Client
- Connects to reverse proxy using TLS
- Provides command-line interface for file operations
- Verifies server certificates using CA certificate

## Certificate Management

### 1. Generate Certificates

Two scripts are provided for certificate generation:
- `certs/create_certs.sh`: Full version with proper CA configuration
- `certs/create_certs_simple.sh`: Simplified version for quick testing

```bash
# Make the script executable
chmod +x certs/create_certs.sh

# Run the certificate generation script
./certs/create_certs.sh
```

This will create:
- A Certificate Authority (CA) in `ca/` directory
- HTTPS server certificate (`https_server.crt` and `https_server.key`)
- Reverse proxy certificate (`reverse_proxy.crt` and `reverse_proxy.key`)

### 2. Certificate Directory Structure

```
certs/
├── ca/
│   ├── private/
│   │   └── cakey.pem         # CA private key
│   ├── cacert.pem            # CA certificate
│   ├── index.txt             # Certificate database
│   ├── serial                # Serial number file
│   └── openssl.cnf           # OpenSSL configuration
├── https_server.crt          # HTTPS server certificate
├── https_server.key          # HTTPS server private key
├── reverse_proxy.crt         # Reverse proxy certificate
└── reverse_proxy.key         # Reverse proxy private key
```

### 3. Deploy Certificates

Use the provided `deploy.sh` script to distribute certificates:

```bash
# Make deploy script executable
chmod +x deploy.sh

# Run deployment
./deploy.sh
```

This will:
1. Generate certificates
2. Copy HTTPS server certificates to VM2 (FreeBSD)
3. Copy reverse proxy certificates to VM1 (GhostBSD)

### 4. Certificate Renewal

Certificates are valid for:
- CA certificate: 10 years (3650 days)
- Server certificates: 1 year (365 days)

To renew certificates:

```bash
# Remove old certificates
rm -rf certs/ca certs/*.crt certs/*.key certs/*.csr

# Regenerate certificates
./certs/create_certs.sh

# Redeploy to servers
./deploy.sh
```

## Setup Instructions

### 1. HTTPS Server Setup (VM2)

```bash
# Install Nginx
pkg install nginx

# Create required directories
sudo mkdir -p /var/www/files/upload
sudo mkdir -p /var/www/files/temp

# Set permissions
sudo chown -R www:www /var/www/files
sudo chmod -R 755 /var/www/files
sudo chmod 775 /var/www/files/upload

# Copy certificates
sudo mkdir -p /etc/nginx/ssl
sudo cp https_server.crt https_server.key cacert.pem /etc/nginx/ssl/

# Start Nginx
sudo service nginx restart
```

### 2. Reverse Proxy Setup (VM1)

```bash
# Install dependencies
pkg install -y openssl pam_ldap gcc gmake

# Build the proxy
make

# Run the proxy
./proxy
```

### 3. Client Usage

```bash
# Build the client
make client

# Run the client
./client <proxy_ip_address>
```

## Available Commands

- `ls`: List files on the server
- `get <filename>`: Download a file
- `put <filename>`: Upload a file
- `exit`: Close the connection

## Security Features

1. **TLS Encryption**: All connections (client-proxy and proxy-server) are encrypted
2. **Certificate Verification**: Validates certificates in both connections
3. **PAM Authentication**: User authentication through system PAM
4. **Isolated Upload Directory**: User uploads are segregated in `/var/www/files/upload`

## Corner Cases Handled

### 1. File Upload Isolation and Security

- All uploaded files are automatically directed to `/var/www/files/upload`
- Prevents unauthorized access to system directories
- Handles directory traversal attempts

**Demonstration:**
```bash
# Attempt to upload to unauthorized location
put ../../../etc/passwd
# Result: File will be saved in upload directory, preventing system access
```

### 2. Concurrent User Authentication

- System properly handles multiple simultaneous authentication attempts
- Maintains separate SSL contexts for each client
- Prevents authentication race conditions

**Demonstration:**
```bash
# Open multiple terminals and run simultaneously
./client <proxy_ip>
# System will handle each authentication independently
```

## Assumptions

1. PAM authentication is configured on the proxy server
2. All necessary certificates are properly generated and placed
3. Network connectivity exists between VMs
4. Required ports (443, 8443) are open in firewalls
5. Sufficient permissions are set for file operations

## Error Handling

- Invalid certificates are rejected
- Failed authentication attempts are logged
- Network disconnections are handled gracefully
- File operation errors return appropriate messages

## Limitations

- Fixed buffer sizes for file transfers
- Single-threaded client implementation
