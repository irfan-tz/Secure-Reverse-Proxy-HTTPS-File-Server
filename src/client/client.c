#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8443
#define BUFFER_SIZE 4096
#define MAX_COMMAND_SIZE 1024

// Initialize OpenSSL
void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Clean up OpenSSL
void cleanup_openssl()
{
    EVP_cleanup();
}

// Create SSL context, load CA certificate, and set verification mode
SSL_CTX *create_ssl_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load CA certificate for server verification
    printf("Loading CA certificate...\n");
    if (!SSL_CTX_load_verify_locations(ctx, "cacert.pem", NULL))
    {
        printf("Failed to load CA certificate from cacert.pem, trying ca/cacert.pem...\n");
        if (!SSL_CTX_load_verify_locations(ctx, "ca/cacert.pem", NULL))
        {
            printf("Failed to load CA certificate\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }
    printf("CA certificate loaded successfully\n");

    // Set verification mode
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    printf("Certificate verification enabled\n");

    return ctx;
}

// Extract HTTP content from a response (skip headers) and return content_start position
char *extract_http_content(char *response, int response_length, int *content_length)
{
    // Look for either \r\n\r\n or \n\n which both signal end of headers
    char *header_end = strstr(response, "\r\n\r\n");
    if (!header_end)
    {
        header_end = strstr(response, "\n\n");
        if (!header_end)
        {
            return NULL; // No header boundary found
        }
        *content_length = response_length - (header_end - response) - 2;
        return header_end + 2; // Skip "\n\n"
    }

    // Calculate content start position and length
    *content_length = response_length - (header_end - response) - 4;
    return header_end + 4; // Skip "\r\n\r\n"
}

size_t process_chunked_data(char *data, size_t len, FILE *fp) {
    size_t bytes_written = 0;
    size_t pos = 0;
    
    while (pos < len) {
        // Find the chunk size line
        char *chunk_size_end = strstr(data + pos, "\r\n");
        if (!chunk_size_end) {
            // Incomplete chunk header, wait for more data
            return bytes_written;
        }
        
        // Extract chunk size
        char chunk_size_str[16] = {0};
        strncpy(chunk_size_str, data + pos, chunk_size_end - (data + pos));
        
        // Parse chunk size (hex string)
        unsigned int chunk_size;
        sscanf(chunk_size_str, "%x", &chunk_size);
        
        // Move past the chunk size line
        pos = (chunk_size_end + 2) - data;
        
        // Check if this is the terminal chunk (size 0)
        if (chunk_size == 0) {
            // End of chunked transfer
            return bytes_written;
        }
        
        // Check if we have enough data for this chunk
        if (pos + chunk_size + 2 > len) {
            // Incomplete chunk, wait for more data
            return bytes_written;
        }
        
        // Write this chunk to the file
        fwrite(data + pos, 1, chunk_size, fp);
        bytes_written += chunk_size;
        
        // Move past this chunk and its trailing CRLF
        pos += chunk_size + 2;
    }
    
    return bytes_written;
}


void handle_file_download(SSL *ssl, const char *filename) {
    char buffer[BUFFER_SIZE] = {0};
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        printf("Error: Could not create file %s\n", filename);
        return;
    }
    
    printf("Downloading %s...\n", filename);
    
    // Variables for tracking HTTP response
    int headers_found = 0;
    int content_length = -1;
    int chunked_encoding = 0;
    int bytes_received = 0;
    char *response_buffer = NULL;
    size_t response_size = 0;
    size_t bytes_written = 0;
    
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        
        if (bytes <= 0) {
            int err = SSL_get_error(ssl, bytes);
            if (err == SSL_ERROR_ZERO_RETURN) {
                // Connection closed cleanly
                break;
            } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Need to retry
                continue;
            } else {
                // Error
                printf("SSL read error: %d\n", err);
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        
        // Append received data to our response buffer
        char *new_buffer = realloc(response_buffer, response_size + bytes + 1);
        if (!new_buffer) {
            printf("Memory allocation failed\n");
            free(response_buffer);
            fclose(fp);
            return;
        }
        
        response_buffer = new_buffer;
        memcpy(response_buffer + response_size, buffer, bytes);
        response_size += bytes;
        response_buffer[response_size] = '\0';
        
        // Process headers if we haven't found them yet
        if (!headers_found) {
            char *header_end = strstr(response_buffer, "\r\n\r\n");
            if (header_end) {
                headers_found = 1;
                *header_end = '\0'; // Temporarily null-terminate the headers
                
                // Check for status code
                char *status_line = response_buffer;
                char *status_end = strstr(status_line, "\r\n");
                if (status_end) {
                    *status_end = '\0';
                    printf("HTTP Response: %s\n", status_line);
                    
                    // Check if it's not a 200 OK
                    if (strstr(status_line, "200 OK") == NULL) {
                        printf("Error: Server returned non-200 status: %s\n", status_line);
                        free(response_buffer);
                        fclose(fp);
                        return;
                    }
                    *status_end = '\r'; // Restore the \r
                }
                
                // Check for Content-Length header
                char *cl_header = strcasestr(response_buffer, "Content-Length:");
                if (cl_header) {
                    sscanf(cl_header, "Content-Length: %d", &content_length);
                    printf("Content-Length: %d bytes\n", content_length);
                }
                
                // Check for Transfer-Encoding: chunked
                if (strcasestr(response_buffer, "Transfer-Encoding: chunked")) {
                    chunked_encoding = 1;
                    printf("Transfer-Encoding: chunked\n");
                }
                
                // Restore the header_end and calculate content offset
                *header_end = '\r';
                int content_offset = (header_end + 4) - response_buffer;
                int content_bytes = response_size - content_offset;
                
                // Write the content portion to file
                if (content_bytes > 0) {
                    if (chunked_encoding) {
                        // Parse and write chunked data
                        char *chunk_start = response_buffer + content_offset;
                        bytes_written += process_chunked_data(chunk_start, content_bytes, fp);
                    } else {
                        // Write normal content
                        fwrite(response_buffer + content_offset, 1, content_bytes, fp);
                        bytes_written += content_bytes;
                    }
                    
                    bytes_received += content_bytes;
                }
                
                // Clear buffer and keep just the unused content
                if (content_bytes > 0) {
                    memmove(response_buffer, response_buffer + content_offset, content_bytes);
                    response_size = content_bytes;
                } else {
                    response_size = 0;
                }
            }
        } else {
            // Headers already processed, handle the data
            if (chunked_encoding) {
                bytes_written += process_chunked_data(response_buffer, response_size, fp);
            } else {
                fwrite(response_buffer, 1, response_size, fp);
                bytes_written += response_size;
            }
            
            bytes_received += response_size;
            response_size = 0;
        }
        
        // Check if we've received the entire content for non-chunked encoding
        if (!chunked_encoding && content_length > 0 && bytes_received >= content_length) {
            printf("Download complete: received %d of %d bytes\n", bytes_received, content_length);
            break;
        }
        
        // For chunked encoding, process_chunked_data will set a flag when done
        if (chunked_encoding && bytes_received > 0 && response_size == 0) {
            // Check if we've seen the terminal chunk
            if (strstr(buffer, "0\r\n\r\n")) {
                printf("Chunked download complete\n");
                break;
            }
        }
    }
    
    free(response_buffer);
    fclose(fp);
    
    if (bytes_written > 0) {
        printf("File downloaded: %s (%zu bytes)\n", filename, bytes_written);
    } else {
        printf("Error: No content received for %s\n", filename);
        remove(filename);
    }
}



int main(int argc, char *argv[])
{
    int sock = 0;
    struct sockaddr_in serv_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[BUFFER_SIZE] = {0};
    char command[MAX_COMMAND_SIZE] = {0};

    // Check if proxy is given
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <proxy_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("Initializing OpenSSL...\n");
    init_openssl();
    ctx = create_ssl_context();
    printf("OpenSSL initialized successfully\n");

    printf("Creating socket...\n");
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return EXIT_FAILURE;
    }
    printf("Socket created successfully\n");

    printf("Setting up server address...\n");
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    printf("Server address set to %s:%d\n", argv[1], PORT);

    // Check if the address is valid
    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return EXIT_FAILURE;
    }

    printf("Connecting to server %s:%d...\n", argv[1], PORT);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return EXIT_FAILURE;
    }
    printf("Connected to server successfully\n");

    printf("Creating SSL connection...\n");
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    printf("SSL connection created\n");

    // Set hostname for SNI
    SSL_set_tlsext_host_name(ssl, argv[1]);
    printf("Performing SSL handshake...\n");

    // Perform SSL handshake
    int ssl_connect_result = SSL_connect(ssl);
    if (ssl_connect_result != 1)
    {
        printf("SSL handshake failed with result: %d\n", ssl_connect_result);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    printf("SSL handshake completed successfully\n");

    // Verify certificate
    int verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK)
    {
        printf("Server certificate verification failed: %d\n", verify_result);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    printf("Connected to %s:%d\n", argv[1], PORT);
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    // Print server certificate info
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Server certificate subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Server certificate issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        printf("No server certificate received\n");
    }

    printf("Waiting for username prompt...\n");
    // Authentication
    memset(buffer, 0, sizeof(buffer));
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0)
    {
        printf("Error reading from server: %d\n", bytes);
        int ssl_error = SSL_get_error(ssl, bytes);
        printf("SSL error: %d\n", ssl_error);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    printf("Received: '%s'\n", buffer); // Username prompt

    fgets(command, sizeof(command), stdin);
    SSL_write(ssl, command, strlen(command));

    memset(buffer, 0, sizeof(buffer));
    SSL_read(ssl, buffer, sizeof(buffer) - 1);
    printf("%s", buffer); // Password prompt

    fgets(command, sizeof(command), stdin);
    SSL_write(ssl, command, strlen(command));

    memset(buffer, 0, sizeof(buffer));
    SSL_read(ssl, buffer, sizeof(buffer) - 1);
    printf("%s", buffer); // Authentication result

    if (strstr(buffer, "Authentication failed") != NULL)
    {
        goto cleanup;
    }

    // Command loop
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            int err = SSL_get_error(ssl, bytes);
            if (err == SSL_ERROR_ZERO_RETURN) {
                printf("Connection closed by server\n");
                break;
            } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                continue;
            } else {
                printf("SSL read error: %d\n", err);
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        
        printf("%s", buffer); // Print prompt or response
        
        // Check if this is a prompt
        if (strstr(buffer, "HTTPS SERVER>") != NULL) {
            memset(command, 0, sizeof(command));
            if (fgets(command, sizeof(command), stdin) == NULL) {
                break;
            }
            
            // Check if get command before sending
            int is_get_command = 0;
            char filename[256] = {0};
            if (strncmp(command, "get ", 4) == 0) {
                is_get_command = 1;
                sscanf(command, "get %255s", filename);
                printf("Preparing to download file: %s\n", filename);
            }
            
            // Send command to server
            SSL_write(ssl, command, strlen(command));
            
            // Check if exit command
            if (strncmp(command, "exit", 4) == 0) {
                // Wait for goodbye message
                memset(buffer, 0, sizeof(buffer));
                SSL_read(ssl, buffer, sizeof(buffer) - 1);
                printf("%s", buffer);
                break;
            }
            
            // Handle file download
            if (is_get_command && strlen(filename) > 0) {
                handle_file_download(ssl, filename);
            }
            // Special handling for put command
            else if (strncmp(command, "put", 3) == 0) {
                char filename[256] = {0};
                sscanf(command, "put %255s", filename);
                
                if (strlen(filename) == 0) {
                    printf("Error: Missing filename. Usage: put <filename>\n");
                    continue;
                }
                
                printf("Preparing to upload file: %s\n", filename);
                
                // Wait for prompt to enter file content
                memset(buffer, 0, sizeof(buffer));
                SSL_read(ssl, buffer, sizeof(buffer) - 1);
                printf("%s", buffer);
                
                // Buffer to store the complete file content
                char *content_buffer = malloc(BUFFER_SIZE * 10);
                if (!content_buffer) {
                    printf("Memory allocation failed\n");
                    continue;
                }
                
                size_t content_length = 0;
                
                // Read file content from stdin
                printf("Enter file content (type EOF on a new line to finish):\n");
                while (1) {
                    memset(command, 0, sizeof(command));
                    if (fgets(command, sizeof(command), stdin) == NULL) {
                        break;
                    }
                    
                    // Check for EOF marker
                    if (strcmp(command, "EOF\n") == 0 || strcmp(command, "EOF\r\n") == 0) {
                        break;
                    }
                    
                    // Append to content buffer
                    size_t line_length = strlen(command);
                    if (content_length + line_length < BUFFER_SIZE * 10) {
                        memcpy(content_buffer + content_length, command, line_length);
                        content_length += line_length;
                    } else {
                        printf("Content too large, truncating\n");
                        break;
                    }
                }
                
                // Send the file content
                SSL_write(ssl, content_buffer, content_length);
                // Send EOF marker to server
                SSL_write(ssl, "EOF", 3);
                
                // Wait for server response
                memset(buffer, 0, sizeof(buffer));
                int response_size = 0;
                while (1) {
                    int bytes = SSL_read(ssl, buffer + response_size, sizeof(buffer) - response_size - 1);
                    if (bytes <= 0) {
                        break;
                    }
                    response_size += bytes;
                    buffer[response_size] = '\0';
                    
                    // Check if we've received a complete response
                    if (strstr(buffer, "\r\n\r\n") != NULL) {
                        if ((size_t)response_size < sizeof(buffer) - 1) {
                            break;
                        }
                    }
                }
                
                printf("%s", buffer);
                free(content_buffer);
            }
        }
    }
    
cleanup:
    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}