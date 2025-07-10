#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <security/pam_appl.h>

#define PORT 8443
#define HTTPS_PORT 443
#define HTTPS_SERVER "192.168.56.6"  // Chupacabra VM2
#define BUFFER_SIZE 4096
#define MAX_COMMAND_SIZE 1024
#define MAX_CONTENT_SIZE (BUFFER_SIZE * 100)  // Limit file content size to prevent overflow

// Structure to hold client connection data
typedef struct {
    int client_socket;
    SSL *client_ssl;
    struct sockaddr_in client_addr;
} client_data;

// Structure for PAM conversation
typedef struct {
    char *username;
    char *password;
} pam_auth_data;

// PAM conversation function
static int pam_conversation(int num_msg, const struct pam_message **msg,
                           struct pam_response **resp, void *appdata_ptr) {
    pam_auth_data *auth_data = (pam_auth_data *)appdata_ptr;
    struct pam_response *response;
    
    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
        return PAM_CONV_ERR;
    
    response = (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
    if (response == NULL)
        return PAM_BUF_ERR;
    
    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_ON:
                response[i].resp = strdup(auth_data->username);
                break;
            case PAM_PROMPT_ECHO_OFF:
                response[i].resp = strdup(auth_data->password);
                break;
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                break;
            default:
                free(response);
                return PAM_CONV_ERR;
        }
    }
    
    *resp = response;
    return PAM_SUCCESS;
}

// Authenticate user with PAM
int authenticate_user(const char *username, const char *password) {
    pam_handle_t *pamh = NULL;
    pam_auth_data auth_data = {
        .username = (char *)username,
        .password = (char *)password
    };
    struct pam_conv conv = {
        .conv = pam_conversation,
        .appdata_ptr = &auth_data
    };
    
    int ret;
    ret = pam_start("login", username, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "PAM start error: %s\n", pam_strerror(pamh, ret));
        return 0;
    }
    
    ret = pam_authenticate(pamh, 0);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "Authentication failed: %s\n", pam_strerror(pamh, ret));
        pam_end(pamh, ret);
        return 0;
    }
    
    ret = pam_acct_mgmt(pamh, 0);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "Account validation failed: %s\n", pam_strerror(pamh, ret));
        pam_end(pamh, ret);
        return 0;
    }
    
    pam_end(pamh, PAM_SUCCESS);
    return 1;
}

// Initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Clean up OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Create SSL context for the proxy server
SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Set the certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "reverse_proxy.crt", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load certificate file 'reverse_proxy.crt'\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, "reverse_proxy.key", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load private key file 'reverse_proxy.key'\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
    
    // Load CA certificate
    if (!SSL_CTX_load_verify_locations(ctx, "ca/cacert.pem", NULL)) {
        fprintf(stderr, "Warning: Could not load CA certificate from ca/cacert.pem\n");
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Continuing without CA certificate verification\n");
    }
    
    return ctx;
}

// Create SSL context for client connection to HTTPS server
SSL_CTX *create_client_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Load CA certificate for server verification
    if (!SSL_CTX_load_verify_locations(ctx, "ca/cacert.pem", NULL)) {
        fprintf(stderr, "Warning: Could not load CA certificate for HTTPS server verification\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("CA certificate loaded for HTTPS server verification\n");
    }
    
    // For testing purposes, you might want to disable strict verification
    // In production, you should use SSL_VERIFY_PEER
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    return ctx;
}


// Connect to HTTPS server
SSL *connect_to_https_server(SSL_CTX *ctx) {
    int server_fd;
    struct sockaddr_in server_addr;
    SSL *ssl;
    
    printf("Connecting to HTTPS server at %s:%d\n", HTTPS_SERVER, HTTPS_PORT);
    
    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation error");
        return NULL;
    }
    
    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(HTTPS_PORT);
    if (inet_pton(AF_INET, HTTPS_SERVER, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(server_fd);
        return NULL;
    }
    
    // Connect to server
    if (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(server_fd);
        return NULL;
    }
    
    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);
    
    // Set hostname for SNI
    SSL_set_tlsext_host_name(ssl, HTTPS_SERVER);
    
    // Perform SSL handshake
    int result = SSL_connect(ssl);
    if (result != 1) {
        fprintf(stderr, "SSL handshake with HTTPS server failed\n");
        ERR_print_errors_fp(stderr);
        int fd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(fd);
        return NULL;
    }
    
    printf("SSL connection to HTTPS server established successfully\n");
    
    // Verify certificate (for logging purposes)
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("HTTPS server certificate subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("HTTPS server certificate issuer: %s\n", line);
        free(line);
        X509_free(cert);
    } else {
        printf("No HTTPS server certificate received\n");
    }
    
    return ssl;
}

int sanitize_filename(const char *input, char *output, size_t output_size) {
    size_t i, j = 0;
    size_t input_len = strlen(input);
    
    // Check for empty input
    if (input_len == 0) {
        return 0;
    }
    
    // Remove leading slashes and dots
    while (input[0] == '/' || input[0] == '.' || input[0] == '\\') {
        input++;
        if (*input == '\0') return 0;
    }
    
    // Process each character
    for (i = 0; i < input_len && j < output_size - 1; i++) {
        // Skip path traversal sequences
        if (input[i] == '.' && (input[i+1] == '.' || input[i+1] == '/')) {
            continue;
        }
        
        // Replace backslashes with forward slashes
        if (input[i] == '\\') {
            output[j++] = '/';
        }
        // Allow only safe characters
        else if ((input[i] >= 'a' && input[i] <= 'z') ||
                 (input[i] >= 'A' && input[i] <= 'Z') ||
                 (input[i] >= '0' && input[i] <= '9') ||
                 input[i] == '_' || input[i] == '-' || 
                 input[i] == '.' || input[i] == '/') {
            output[j++] = input[i];
        }
    }
    
    output[j] = '\0';
    
    // Ensure no double slashes
    for (i = 0; i < j - 1; i++) {
        if (output[i] == '/' && output[i+1] == '/') {
            memmove(&output[i], &output[i+1], j - i);
            j--;
            i--;
        }
    }
    
    // Ensure we didn't end up with an empty string
    return (j > 0);
}


// Extract content from HTTP response (skip headers)
char* extract_http_content(char* response, int response_length, int* content_length) {
    char* header_end = strstr(response, "\r\n\r\n");
    if (!header_end) {
        return NULL; // No header boundary found
    }
    
    // Calculate content start position and length
    char* content_start = header_end + 4; // Skip "\r\n\r\n"
    *content_length = response_length - (content_start - response);
    
    return content_start;
}

// Handle 'ls' command
void handle_ls(SSL *client_ssl) {
    char buffer[BUFFER_SIZE];
    int bytes;
    
    // Create a new connection to the HTTPS server for this command
    SSL_CTX *https_ctx = create_client_ssl_context();
    SSL *https_ssl = connect_to_https_server(https_ctx);
    if (!https_ssl) {
        SSL_write(client_ssl, "Error: Failed to connect to HTTPS server\n", 42);
        SSL_CTX_free(https_ctx);
        return;
    }
    
    // Send HTTP GET request to server
    const char *request = "GET / HTTP/1.1\r\nHost: " HTTPS_SERVER "\r\nConnection: close\r\n\r\n";
    int write_result = SSL_write(https_ssl, request, strlen(request));
    if (write_result <= 0) {
        SSL_write(client_ssl, "Error: Failed to send request to HTTPS server\n", 45);
        int fd = SSL_get_fd(https_ssl);
        SSL_shutdown(https_ssl);
        SSL_free(https_ssl);
        close(fd);
        SSL_CTX_free(https_ctx);
        return;
    }
    
    // Read response from server and send to client
    while (1) {
        bytes = SSL_read(https_ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            int ssl_error = SSL_get_error(https_ssl, bytes);
            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                // Connection closed cleanly
                break;
            } else if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                // Need to retry
                continue;
            } else {
                // Error
                break;
            }
        }
        
        buffer[bytes] = '\0';
        SSL_write(client_ssl, buffer, bytes);
    }
    
    // Clean up the HTTPS connection
    int fd = SSL_get_fd(https_ssl);
    SSL_shutdown(https_ssl);
    SSL_free(https_ssl);
    close(fd);
    SSL_CTX_free(https_ctx);
}

// Handle 'get' command
void handle_get(SSL *client_ssl, const char *filename) {
    char buffer[BUFFER_SIZE];
    int bytes;
    
    // Create a new connection to the HTTPS server for this command
    SSL_CTX *https_ctx = create_client_ssl_context();
    SSL *https_ssl = connect_to_https_server(https_ctx);
    if (!https_ssl) {
        SSL_write(client_ssl, "Error: Failed to connect to HTTPS server\n", 42);
        SSL_CTX_free(https_ctx);
        return;
    }
    
    printf("Connected to HTTPS server for downloading file: %s\n", filename);
    
    // Sanitize filename to prevent directory traversal attacks
    char safe_filename[256];
    if (!sanitize_filename(filename, safe_filename, sizeof(safe_filename))) {
        SSL_write(client_ssl, "Error: Invalid filename\n", 24);
        goto cleanup;
    }
    
    // Send HTTP GET request to server for the file
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request), 
             "GET /%s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "User-Agent: SecureReverseProxy/1.0\r\n"
             "\r\n", 
             safe_filename, HTTPS_SERVER);
    printf("Constructed PUT request:\n%s\n", request);
    
    int write_result = SSL_write(https_ssl, request, strlen(request));
    if (write_result <= 0) {
        SSL_write(client_ssl, "Error: Failed to send request to HTTPS server\n", 45);
        goto cleanup;
    }
    
    printf("GET request sent to HTTPS server for %s\n", safe_filename);
    
    // First, read the HTTP headers to check status code
    char response_headers[BUFFER_SIZE] = {0};
    int header_size = 0;
    int headers_complete = 0;
    
    // Read headers first to validate response
    while (!headers_complete && header_size < BUFFER_SIZE - 1) {
        bytes = SSL_read(https_ssl, buffer, 1); // Read byte by byte to find header end
        if (bytes <= 0) {
            int ssl_error = SSL_get_error(https_ssl, bytes);
            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                break; // Connection closed
            } else if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue; // Try again
            } else {
                SSL_write(client_ssl, "Error: Failed to read response from HTTPS server\n", 49);
                goto cleanup;
            }
        }
        
        response_headers[header_size++] = buffer[0];
        response_headers[header_size] = '\0';
        
        // Check if we've reached the end of headers
        if (header_size >= 4 && 
            response_headers[header_size-4] == '\r' && 
            response_headers[header_size-3] == '\n' &&
            response_headers[header_size-2] == '\r' && 
            response_headers[header_size-1] == '\n') {
            headers_complete = 1;
        }
    }
    
    // Verify the response status code
    if (!headers_complete || strstr(response_headers, "HTTP/1.1 200") == NULL) {
        // Send headers and error message to client
        SSL_write(client_ssl, response_headers, header_size);
        if (!headers_complete) {
            SSL_write(client_ssl, "\r\n\r\nError: Incomplete response from server\n", 42);
        }
        goto cleanup;
    }
    
    // Send the headers to the client
    SSL_write(client_ssl, response_headers, header_size);
    
    // Now read and send the rest of the file
    while (1) {
        bytes = SSL_read(https_ssl, buffer, sizeof(buffer));
        if (bytes <= 0) {
            int ssl_error = SSL_get_error(https_ssl, bytes);
            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                // Connection closed cleanly
                break;
            } else if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                // Need to retry
                continue;
            } else {
                // Error occurred
                break;
            }
        }
        
        // Send data to client
        int client_bytes = SSL_write(client_ssl, buffer, bytes);
        if (client_bytes <= 0) {
            // Error writing to client
            break;
        }
    }
    
cleanup:
    // Clean up the HTTPS connection
    int fd = SSL_get_fd(https_ssl);
    SSL_shutdown(https_ssl);
    SSL_free(https_ssl);
    close(fd);
    SSL_CTX_free(https_ctx);
    printf("Completed file download request for %s\n", safe_filename);
}


// Handle 'put' command
void handle_put(SSL *client_ssl, const char *filename, const char *content, size_t content_length) {
    char buffer[BUFFER_SIZE];
    int bytes;
    
    // Create a new connection to the HTTPS server for this command
    SSL_CTX *https_ctx = create_client_ssl_context();
    SSL *https_ssl = connect_to_https_server(https_ctx);
    if (!https_ssl) {
        SSL_write(client_ssl, "Error: Failed to connect to HTTPS server\n", 42);
        SSL_CTX_free(https_ctx);
        return;
    }
    
    // Sanitize filename to prevent directory traversal attacks
    // char safe_filename[256];
    // if (!sanitize_filename(filename, safe_filename, sizeof(safe_filename))) {
    //     SSL_write(client_ssl, "Error: Invalid filename\n", 24);
    //     goto cleanup;
    // }
    
    
    
    // Build the HTTP PUT request
    char request[BUFFER_SIZE * 2]; // Larger buffer for headers
    char safe_filename[256];
    snprintf(safe_filename, sizeof(safe_filename), "upload/%s", filename); // prepend "upload/"

    snprintf(request, sizeof(request),
    "PUT /%s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Content-Length: %zu\r\n"
    "Content-Type: application/octet-stream\r\n"
    "Connection: close\r\n\r\n",
    safe_filename, HTTPS_SERVER, content_length);
    
    printf("Sending PUT request:\n%s\n", request);
    printf("Sending PUT request for file: %s (content length: %zu bytes)\n", safe_filename, content_length);
    
    // Send headers
    int write_result = SSL_write(https_ssl, request, strlen(request));
    if (write_result <= 0) {
        SSL_write(client_ssl, "Error: Failed to send request headers to HTTPS server\n", 53);
        goto cleanup;
    }
    
    // Send file content
    const char *ptr = content;
    size_t remaining = content_length;
    
    while (remaining > 0) {
        size_t chunk_size = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : remaining;
        write_result = SSL_write(https_ssl, ptr, chunk_size);
        
        if (write_result <= 0) {
            SSL_write(client_ssl, "Error: Failed to send file content to HTTPS server\n", 51);
            goto cleanup;
        }
        
        ptr += write_result;
        remaining -= write_result;
    }
    
    printf("PUT request and content sent successfully\n");
    
    // Read and forward the server response
    int total_bytes = 0;
    char response_buffer[BUFFER_SIZE * 4] = {0};
    
    while (1) {
        bytes = SSL_read(https_ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            int ssl_error = SSL_get_error(https_ssl, bytes);
            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                break; // Connection closed
            } else if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue; // Retry
            } else {
                break; // Error
            }
        }
        
        // Forward to client
        SSL_write(client_ssl, buffer, bytes);
        
        // Store for logging
        if ((size_t)(total_bytes + bytes) < sizeof(response_buffer)) {
            memcpy(response_buffer + total_bytes, buffer, bytes);
            total_bytes += bytes;
        }
    }
    
    // Log response status
    if (strstr(response_buffer, "201 Created") || strstr(response_buffer, "204 No Content")) {
        printf("File '%s' uploaded successfully\n", safe_filename);
    } else {
        printf("PUT request failed with response: %.100s...\n", response_buffer);
    }
    
cleanup:
    // Clean up the HTTPS connection
    int fd = SSL_get_fd(https_ssl);
    SSL_shutdown(https_ssl);
    SSL_free(https_ssl);
    close(fd);
    SSL_CTX_free(https_ctx);
}

// Handle client connection
void *handle_client(void *arg) {
    client_data *data = (client_data *)arg;
    int client_socket = data->client_socket;
    SSL *client_ssl = data->client_ssl;
    struct sockaddr_in client_addr = data->client_addr;
    char client_ip[INET_ADDRSTRLEN];
    
    // Free the client data structure
    free(data);
    
    // Get client IP address
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("Client connected: %s\n", client_ip);
    
    // Perform SSL handshake
    if (SSL_accept(client_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // Authenticate user
    char username[64] = {0};
    char password[64] = {0};
    
    // Send login prompt
    SSL_write(client_ssl, "Username: ", 10);
    
    int bytes = SSL_read(client_ssl, username, sizeof(username) - 1);
    if (bytes <= 0) {
        fprintf(stderr, "Error reading username\n");
        goto cleanup;
    }
    username[strcspn(username, "\r\n")] = 0; // Remove newline
    
    SSL_write(client_ssl, "Password: ", 10);
    
    bytes = SSL_read(client_ssl, password, sizeof(password) - 1);
    if (bytes <= 0) {
        fprintf(stderr, "Error reading password\n");
        goto cleanup;
    }
    password[strcspn(password, "\r\n")] = 0; // Remove newline
    
    if (!authenticate_user(username, password)) {
        SSL_write(client_ssl, "Authentication failed\n", 22);
        goto cleanup;
    }
    
    SSL_write(client_ssl, "Authentication successful\n", 26);
    
    // Command loop
    char command[MAX_COMMAND_SIZE];
    while (1) {
        // Send prompt
        SSL_write(client_ssl, "HTTPS SERVER> ", 14);
        
        // Read command
        memset(command, 0, sizeof(command));
        bytes = SSL_read(client_ssl, command, sizeof(command) - 1);
        if (bytes <= 0) {
            fprintf(stderr, "Client disconnected during command read\n");
            break;
        }
        
        command[strcspn(command, "\r\n")] = 0; // Remove newline
        printf("Received command: '%s'\n", command);
        
        // Parse command
        char cmd_copy[MAX_COMMAND_SIZE];
        strncpy(cmd_copy, command, MAX_COMMAND_SIZE - 1);
        cmd_copy[MAX_COMMAND_SIZE - 1] = '\0';
        
        char *cmd = strtok(cmd_copy, " ");
        if (cmd == NULL) {
            continue;
        }
        
        if (strcmp(cmd, "ls") == 0) {
            printf("Executing ls command\n");
            handle_ls(client_ssl);
        } else if (strcmp(cmd, "get") == 0) {
            char *filename = strtok(NULL, " ");
            if (filename) {
                printf("Executing get command for file: %s\n", filename);
                handle_get(client_ssl, filename);
            } else {
                SSL_write(client_ssl, "Usage: get <filename>\n", 22);
            }
        } else if (strcmp(cmd, "put") == 0) {
            char *filename = strtok(NULL, " ");
            if (filename) {
                printf("Executing put command for file: %s\n", filename);
                
                // Sanitize filename
                char safe_filename[256];
                if (!sanitize_filename(filename, safe_filename, sizeof(safe_filename))) {
                    SSL_write(client_ssl, "Error: Invalid filename\n", 24);
                    continue;
                }
                
                // Read file content from client
                SSL_write(client_ssl, "Enter file content (type EOF on a new line to finish):\n", 53);
                
                char *content_buffer = malloc(MAX_CONTENT_SIZE);
                if (!content_buffer) {
                    SSL_write(client_ssl, "Error: Memory allocation failed\n", 32);
                    continue;
                }
                
                memset(content_buffer, 0, MAX_CONTENT_SIZE);
                size_t content_length = 0;
                char line_buffer[BUFFER_SIZE];
                int eof_received = 0;
                
                while (!eof_received) {
                    memset(line_buffer, 0, sizeof(line_buffer));
                    int bytes = SSL_read(client_ssl, line_buffer, sizeof(line_buffer) - 1);
                    if (bytes <= 0) {
                        free(content_buffer);
                        fprintf(stderr, "Client disconnected during file upload\n");
                        goto cleanup;
                    }
                    
                    // Check if "EOF" is present anywhere in the received data
                    char *eof_pos = strstr(line_buffer, "EOF");
                    if (eof_pos != NULL) {
                        // Calculate the length of content before "EOF"
                        size_t valid_bytes = eof_pos - line_buffer;
                        memcpy(content_buffer + content_length, line_buffer, valid_bytes);
                        content_length += valid_bytes;
                        eof_received = 1;
                        break;
                    } else {
                        memcpy(content_buffer + content_length, line_buffer, bytes);
                        content_length += bytes;
                    }
                }
                
                // Only proceed if we have content to upload
                if (content_length > 0) {
                    printf("Received %zu bytes of content for file %s\n", content_length, safe_filename);
                    handle_put(client_ssl, safe_filename, content_buffer, content_length);
                } else {
                    SSL_write(client_ssl, "Error: No content received for upload\n", 38);
                }
                
                free(content_buffer);
            } else {
                SSL_write(client_ssl, "Usage: put <filename>\n", 22);
            }
        } else if (strcmp(cmd, "exit") == 0) {
            SSL_write(client_ssl, "Goodbye!\n", 9);
            break;
        } else {
            SSL_write(client_ssl, "Unknown command. Available commands: ls, get, put, exit\n", 56);
        }
    }
    
cleanup:
    // Clean up client connection
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close(client_socket);
    printf("Client disconnected: %s\n", client_ip);
    return NULL;
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    SSL_CTX *ctx;
    
    // Print current working directory
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("Current working directory: %s\n", cwd);
    } else {
        perror("getcwd() error");
    }
    
    // Check if certificate files exist
    FILE *f;
    if ((f = fopen("reverse_proxy.crt", "r"))) {
        printf("reverse_proxy.crt exists\n");
        fclose(f);
    } else {
        printf("reverse_proxy.crt does not exist\n");
    }
    
    if ((f = fopen("reverse_proxy.key", "r"))) {
        printf("reverse_proxy.key exists\n");
        fclose(f);
    } else {
        printf("reverse_proxy.key does not exist\n");
    }
    
    if ((f = fopen("ca/cacert.pem", "r"))) {
        printf("ca/cacert.pem exists\n");
        fclose(f);
    } else {
        printf("ca/cacert.pem does not exist\n");
    }
    
    // Initialize OpenSSL
    init_openssl();
    ctx = create_ssl_context();
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    // Bind socket to port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Reverse proxy started on port %d\n", PORT);
    printf("Ready to accept connections\n");
    
    // Accept connections
    while (1) {
        int client_socket;
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        // Create SSL connection
        SSL *client_ssl = SSL_new(ctx);
        SSL_set_fd(client_ssl, client_socket);
        
        // Create client data structure
        client_data *data = malloc(sizeof(client_data));
        if (!data) {
            perror("Failed to allocate memory for client data");
            SSL_free(client_ssl);
            close(client_socket);
            continue;
        }
        
        data->client_socket = client_socket;
        data->client_ssl = client_ssl;
        data->client_addr = client_addr;
        
        // Create thread to handle client
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, data) != 0) {
            perror("Thread creation failed");
            free(data);
            SSL_free(client_ssl);
            close(client_socket);
            continue;
        }
        
        // Detach thread
        pthread_detach(thread_id);
    }
    
    // Clean up
    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    
    return 0;
}