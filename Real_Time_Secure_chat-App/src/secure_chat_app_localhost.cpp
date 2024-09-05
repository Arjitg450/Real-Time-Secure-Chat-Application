#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#define MAX_BUF_SIZE 1024
#define SERVER_PORT 12345

#include <sys/poll.h>
#include <cstring>   //For strlen()
#include <unistd.h> //For close()

#include <openssl/err.h>
#include <openssl/rand.h>

#define COOKIE_SECRET_LENGTH 16

unsigned char cookie_secret[COOKIE_SECRET_LENGTH];

void initialize_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}


int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    unsigned char buffer[1024];
    unsigned char *p;

    if (RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH) <= 0) {
        std::cerr << "RAND_bytes error" << std::endl;
        return 0;
    }

    p = buffer;
    memcpy(p, &ssl, sizeof(ssl));
    p += sizeof(ssl);
    memcpy(p, cookie_secret, COOKIE_SECRET_LENGTH);
    *cookie_len = sizeof(ssl) + COOKIE_SECRET_LENGTH;

    memcpy(cookie, buffer, *cookie_len);

    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    unsigned char buffer[1024];
    unsigned int verify_len = sizeof(ssl) + COOKIE_SECRET_LENGTH;

    if (cookie_len != verify_len)
        return 0;

    memcpy(buffer, &ssl, sizeof(ssl));
    memcpy(buffer + sizeof(ssl), cookie_secret, COOKIE_SECRET_LENGTH);

    return memcmp(cookie, buffer, verify_len) == 0;
}


void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

std::string SERVER_IP="127.0.0.1";
int PORT = 1234; 
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    // This function is called during the certificate verification process.
    // It allows custom validation logic to be implemented.

    // You can perform additional verification checks here if needed.
    // For example, you can check the certificate's issuer, expiration date, etc.

    if (!preverify_ok) {
        // If preverify_ok is false, the certificate failed some basic checks.
        // You can log the error or perform additional actions if needed.
        // For simplicity, we'll just print an error message.
        fprintf(stderr, "Certificate verification failed.\n");
    }

    // Return 1 to indicate that the certificate is considered valid,
    // or 0 to indicate that the certificate is considered invalid.
    // You can customize the return value based on your validation logic.
    return preverify_ok;
}

void handle_server_mode() {
    // Step 1: Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Step 2: Create a UDP Socket and Bind it to a Port
    int server_fd = socket(AF_INET, SOCK_DGRAM, 0); // Use AF_INET for IPv4
    if (server_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Set to loopback address
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    const char * CHAT_OK_REPLY= "chat_ok_reply";
    const char * HELLO_SSL_SERVER="chat_START_SSL_ACK";
    
    // Receive data from client
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[1024]; // Assuming a buffer size of 1024 bytes, adjust as needed

    ssize_t valread = recvfrom(server_fd, buffer, sizeof(buffer), 0,
                            (struct sockaddr *)&client_addr, &addr_len);
    if (valread == -1) {
        perror("recvfrom");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Extract client address and port
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    printf("Received %zd bytes from %s:%d\n", valread, client_ip, client_port);
    printf("Message from client: %s\n", buffer);

    ssize_t valsent = sendto(server_fd, CHAT_OK_REPLY, strlen(CHAT_OK_REPLY), 0,
                            (const struct sockaddr *)&client_addr, sizeof(client_addr));
    if (valsent == -1) {
        perror("sendto");
        close(server_fd);
        exit(EXIT_FAILURE);
    }


    // Clean the buffer
memset(buffer, 0, sizeof(buffer));

// Receive second message from the client
ssize_t valueread = recvfrom(server_fd, buffer, sizeof(buffer), 0,
                            (struct sockaddr *)&client_addr, &addr_len);
if (valueread == -1) {
    perror("recvfrom");
    close(server_fd);
    exit(EXIT_FAILURE);
}

// Send second reply to the client
ssize_t valuesent = sendto(server_fd, HELLO_SSL_SERVER, strlen(HELLO_SSL_SERVER), 0,
                            (const struct sockaddr *)&client_addr, sizeof(client_addr));
if (valuesent == -1) {
    perror("sendto");
    close(server_fd);
    exit(EXIT_FAILURE);
}

printf("Received %zd bytes from %s:%d\n", valueread, client_ip, client_port);
printf("Message from client: %s\n", buffer);
// Clean the buffer again
memset(buffer, 0, sizeof(buffer));


    // Step 3: Initialize SSL Context for the Server
    SSL_CTX *ssl_ctx = SSL_CTX_new(DTLS_server_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Error creating DTLS context.\n");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    SSL_CTX_set_cookie_generate_cb(ssl_ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ssl_ctx, verify_cookie);
    // Step 4: Load Certificates and Keys
    if (SSL_CTX_use_certificate_file(ssl_ctx, "bob.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, "bob.key", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading certificate or private key.\n");
        close(server_fd);
        SSL_CTX_free(ssl_ctx);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_load_verify_locations(ssl_ctx, "root.crt", NULL) != 1) {
    fprintf(stderr, "Error loading CA certificates.\n");
    close(server_fd);
    SSL_CTX_free(ssl_ctx);
    exit(EXIT_FAILURE);
}

 if (SSL_CTX_load_verify_locations(ssl_ctx, "int.crt", NULL) != 1) {
    fprintf(stderr, "Error loading CA certificates.\n");
    close(server_fd);
    SSL_CTX_free(ssl_ctx);
    exit(EXIT_FAILURE);
}
    // Step 5: Configure SSL Context for the Client
    try{
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_callback);
        std ::cout<<"This happened";
    }
    catch(const std::exception& e){
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
    // Set up verification callback function
    SSL_CTX_set_verify_depth(ssl_ctx, 2);
  

    // Step 4: Enable session ticket support
    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);

    // Step 5: Listen for Incoming DTLS Handshake Requests
    while (1) {
        
    // Step 6: Accept Client Connections
    struct sockaddr_in6 client_addr;
    SSL *ssl = SSL_new(ssl_ctx);
    BIO *bio = BIO_new_dgram(server_fd, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);
    
    // Enable cookie exchange
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
    
    int res = DTLSv1_listen(ssl,(BIO_ADDR *) &client_addr);
    if(res<0){
        std::cout <<"There is an error in listen";
    }

    // Wait for incoming connections
    while (SSL_accept(ssl) <= 0) {
        // Error occurred during SSL_accept
        int ssl_error = SSL_get_error(ssl, -1);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            // No data available for reading or writing, continue waiting
            continue;
        } else {
            // Other error occurred, handle accordingly
            std::cerr << "Error occurred during SSL_accept." << std::endl;
            break;
        }
    }


// Now the DTLS handshake has been successfully completed, proceed with chat messaging


        // Handle chat messaging

        char buffer[MAX_BUF_SIZE];
        int len;

        // Receive messages from the client
        while ((len = SSL_read(ssl, buffer, MAX_BUF_SIZE)) > 0) {
            // Null-terminate the received message
            buffer[len] = '\0';

            // Display the received message
            std::cout << "Client: " << buffer << std::endl;

            // Get user input for the server's response
            std::cout << "Server (You): ";
            std::cin.getline(buffer, MAX_BUF_SIZE);

            // Send the server's response to the client
            SSL_write(ssl, buffer, strlen(buffer));
        }

        if (len < 0) {
            // Error occurred during SSL_read
            int ssl_error = SSL_get_error(ssl, len);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                // No data available for reading, continue waiting for messages
                continue;
            } else {
                // Other error occurred, handle accordingly
                std::cerr << "Error occurred during SSL_read." << std::endl;
                break;
            }
        }

        // Step 8: Clean up SSL object
        SSL_free(ssl);
    }

    // Clean up SSL context and close socket
    SSL_CTX_free(ssl_ctx);
    close(server_fd);
}
void handle_client_mode(const std::string& server_hostname) {
    // Step 1: Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    const char * CHAT_HELLO="chat_hello";
    const char * hello_ssl_client="chat_START_SSL";
    
    std::cout << "Please enter the Port on Which to connect to the Server..." << std::endl;

    char buffer[2048] = {0};

    const char* hello_client = "chat_hello";

    std::string ip_address = "127.0.0.1";
    const char* start_ssl = "chat_START_SSL";
    struct sockaddr_in address;

    address.sin_port = htons(SERVER_PORT);
    address.sin_family = AF_INET;
    int addr_len = sizeof(address);
    address.sin_addr.s_addr = inet_addr("127.0.0.1");

    memset(&(address.sin_zero), '\0', 8);
    int client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
   

    if (client_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (connect(client_socket, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("connect");
        close(client_socket);
        //SSL_CTX_free(ssl_ctx);
        exit(EXIT_FAILURE);
    }

    // Send data to server
    ssize_t val_sent = sendto(client_socket, CHAT_HELLO, strlen(CHAT_HELLO), 0,
                            (const struct sockaddr *)&address, sizeof(address));
    if (val_sent == -1) {
        perror("sendto");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

// Receive response from server
ssize_t val_read = recvfrom(client_socket, buffer, sizeof(buffer), 0, NULL, NULL);
if (val_read == -1) {
    perror("recvfrom");
    close(client_socket);
    exit(EXIT_FAILURE);
}


// Clean the buffer
memset(buffer, 0, sizeof(buffer));

// Send "start_ssl" message to server
ssize_t value_sent = sendto(client_socket, start_ssl, strlen(start_ssl), 0,
                            (const struct sockaddr *)&address, sizeof(address));
if (value_sent == -1) {
    perror("sendto");
    close(client_socket);
    exit(EXIT_FAILURE);
}

// Receive response from server
ssize_t value_read = recvfrom(client_socket, buffer, sizeof(buffer), 0, NULL, NULL);
if (value_read == -1) {
    perror("recvfrom");
    close(client_socket);
    exit(EXIT_FAILURE);
}

printf("Received %zd bytes from server\n", value_read);
printf("Message from server: %s\n", buffer);
    if (client_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }


printf("Received %zd bytes from server\n", val_read);
printf("Message from server: %s\n", buffer);
    if (client_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Step 3: Initialize SSL Context for the Client
    SSL_CTX *ssl_ctx = SSL_CTX_new(DTLS_client_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Error creating DTLS context.\n");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Load client certificate
if (SSL_CTX_use_certificate_file(ssl_ctx, "alice.crt", SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Error loading client certificate.\n");
    close(client_socket);
    SSL_CTX_free(ssl_ctx);
    exit(EXIT_FAILURE);
}

// Load client private key
if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "alice.key", SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Error loading client private key.\n");
    close(client_socket);
    SSL_CTX_free(ssl_ctx);
    exit(EXIT_FAILURE);
}

// If CA certificates are needed for server certificate verification:
// Load CA certificates
if (SSL_CTX_load_verify_locations(ssl_ctx, "ca_chain.crt", NULL) != 1) {
    fprintf(stderr, "Error loading CA certificates.\n");
    close(client_socket);
    SSL_CTX_free(ssl_ctx);
    exit(EXIT_FAILURE);
}
    // Step 5: Configure SSL Context for the Client
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    // Set up verification callback function
    SSL_CTX_set_verify_depth(ssl_ctx, 2); // Adjust verification depth if needed

    // Configure SSL context options
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    // Step 6: Connect to the Server 

    // Step 7: Set up DTLS connection
    SSL *ssl = SSL_new(ssl_ctx);
    // BIO *bio = BIO_new_dgram(client_fd, BIO_NOCLOSE);
    // SSL_set_bio(ssl, bio, bio);

    // Enable cookie exchange
   // SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
    SSL_set_fd(ssl,client_socket);
    // Perform the DTLS handshake
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "Error performing DTLS handshake.\n");
        close(client_socket);
        SSL_CTX_free(ssl_ctx);
        exit(EXIT_FAILURE);
    }

    // Step 8: Handle chat messaging
    // Implement chat messaging logic using SSL_read() and SSL_write()

    // Receive and send messages until termination
    while (true) {
    // Get user input for the client's message
    std::cout << "Client (You): ";
    std::cin.getline(buffer, MAX_BUF_SIZE);

    // Send the message to the server
    if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
        // Error occurred during SSL_write
        int ssl_error = SSL_get_error(ssl, -1);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            // No data available for writing, continue waiting
            continue;
        } else {
            // Other error occurred, handle accordingly
            std::cerr << "Error occurred during SSL_write." << std::endl;
            break;
        }
    }

    // Receive a message from the server
    int len = SSL_read(ssl, buffer, MAX_BUF_SIZE);
    if (len > 0) {
        buffer[len] = '\0'; // Null-terminate the received message
        std::cout << "Server: " << buffer << std::endl; // Print the received message
    } else if (len == 0) {
        // Connection closed by the server
        std::cerr << "Connection closed by the server." << std::endl;
        break;
    } else {
        // Error occurred during SSL_read
        int ssl_error = SSL_get_error(ssl, len);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            // No data available for reading, continue waiting
            continue;
        } else {
            // Other error occurred, handle accordingly
            std::cerr << "Error occurred during SSL_read." << std::endl;
            break;
        }
    }
}


// End of chat messaging

    // Step 9: Clean up SSL resources
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(client_socket);
}


int main(int argc, char *argv[]) {
    int opt;
    std::string server_hostname;
    bool server_mode = false;

    while ((opt = getopt(argc, argv, "sc:")) != -1) {
        switch (opt) {
            case 's':
                server_mode = true;
                break;
            case 'c':
                server_hostname = optarg;
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " [-s | -c serverhostname]" << std::endl;
                exit(EXIT_FAILURE);
        }
    }

    initialize_openssl();

    if (server_mode) {
        handle_server_mode();
    } else if (!server_hostname.empty()) {
        handle_client_mode(server_hostname);
    } else {
        std::cerr << "Usage: " << argv[0] << " [-s | -c serverhostname]" << std::endl;
        exit(EXIT_FAILURE);
    }

    cleanup_openssl();
    return 0;
}