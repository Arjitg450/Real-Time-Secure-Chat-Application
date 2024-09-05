#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_BUF_SIZE 1024
#define SERVER_PORT 45678

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

//std::string SERVER_IP=server_ip;
int PORT = 4678;
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
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Set to loopback address
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
    std::cout << "Message from Alice : " <<buffer<< std::endl;
const char * CHAT_HELLO="chat_hello";



         // Convert the host's address to a string
    const char* server_ip = "172.31.0.3";
    //std::cout << "Server IP resolved to: " << server_ip << std::endl;
    //const char* hello_client = "chat_hello";

   // std::string ip_address = "127.0.0.1";
    const char* start_ssl = "chat_START_SSL";
    struct sockaddr_in address_tc;
 address_tc.sin_port = htons(SERVER_PORT); 
    address_tc.sin_family = AF_INET;
    int addr_len_tc = sizeof(address_tc);
    address_tc.sin_addr.s_addr = inet_addr(server_ip);

    memset(&(address_tc.sin_zero), '\0', 8);
    int client_socket_tc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);


    if (client_socket_tc == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (connect(client_socket_tc, (struct sockaddr *)&address_tc, sizeof(address_tc)) == -1) {
        perror("connect");
        close(client_socket_tc);
        //SSL_CTX_free(ssl_ctx);
        exit(EXIT_FAILURE);
    }
    // Send data to server
    memset(buffer, 0, sizeof(buffer));
    ssize_t val_sent_tc = sendto(client_socket_tc, CHAT_HELLO, strlen(CHAT_HELLO), 0,
                            (const struct sockaddr *)&address_tc, sizeof(address_tc));
    if (val_sent_tc == -1) {
        perror("sendto");
        close(client_socket_tc);
  exit(EXIT_FAILURE);
    }
memset(buffer, 0, sizeof(buffer));
// Receive response from server
ssize_t val_read_tc = recvfrom(client_socket_tc, buffer, sizeof(buffer), 0, NULL, NULL);
if (val_read_tc == -1) {
    perror("recvfrom");
    close(client_socket_tc);
    exit(EXIT_FAILURE);
}


//printf("Received %zd bytes from server\n", val_read_tc);
printf("Message from server: %s\n", buffer);
    if (client_socket_tc == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

// Clean the buffer
memset(buffer, 0, sizeof(buffer));



 // Extract client address and port
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    //printf("Received %zd bytes from %s:%d\n", valread, client_ip, client_port);
    //printf("Message from client: %s\n", buffer);//on server side

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
 std::cout << "Message from Alice : " <<buffer<< std::endl;

// Send "start_ssl" message to server
ssize_t value_sent_tc = sendto(client_socket_tc, start_ssl, strlen(start_ssl), 0,
                            (const struct sockaddr *)&address_tc, sizeof(address_tc));
if (value_sent_tc == -1) {
    perror("sendto");
    close(client_socket_tc);
    exit(EXIT_FAILURE);
}



// Receive response from server
ssize_t value_read = recvfrom(client_socket_tc, buffer, sizeof(buffer), 0, NULL, NULL);
if (value_read == -1) {
    perror("recvfrom");
    close(client_socket_tc);
    exit(EXIT_FAILURE);
}
printf("Message from server/see: %s\n", buffer);

// // Send second reply to the client
// int flag=0;
// if (strcmp(buffer, "chat_START_NORMAL") == 0){
// HELLO_SSL_SERVER="chat_START_NORMAL_Ok";
// flag=1;
// }

ssize_t valuesent = sendto(server_fd,HELLO_SSL_SERVER , strlen(HELLO_SSL_SERVER), 0,
                            (const struct sockaddr *)&client_addr, sizeof(client_addr));
if (valuesent == -1) {
    perror("sendto");
    close(server_fd);
    exit(EXIT_FAILURE);
}
//printf("Received %zd bytes from %s:%d\n", valueread, client_ip, client_port);
//printf("Message from client/checking: %s\n", buffer);

////////////////////////////////////////////--------------------------------------------//////////////////////////////
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
    if (SSL_CTX_use_certificate_file(ssl_ctx, "fakebob.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, "fakebob.key", SSL_FILETYPE_PEM) <= 0) {
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

    }
    catch(const std::exception& e){
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
    // Set up verification callback function
    SSL_CTX_set_verify_depth(ssl_ctx, 2);


    // Step 4: Enable session ticket support
    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);





    // Step 3: Initialize SSL Context for the Client
    SSL_CTX *ssl_ctx_tc = SSL_CTX_new(DTLS_client_method());
    if (!ssl_ctx_tc) {
        fprintf(stderr, "Error creating DTLS context.\n");
        close(client_socket_tc);
        exit(EXIT_FAILURE);
    }

    // Load client certificate
if (SSL_CTX_use_certificate_file(ssl_ctx_tc, "fakealice.crt", SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Error loading client certificate.\n");
    close(client_socket_tc);
    SSL_CTX_free(ssl_ctx_tc);
    exit(EXIT_FAILURE);
}

// Load client private key
if (SSL_CTX_use_PrivateKey_file(ssl_ctx_tc, "fakealice.key", SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Error loading client private key.\n");
    close(client_socket_tc);
    SSL_CTX_free(ssl_ctx_tc);
    exit(EXIT_FAILURE);
}

// If CA certificates are needed for server certificate verification:
// Load CA certificates
if (SSL_CTX_load_verify_locations(ssl_ctx_tc, "ca_chain.crt", NULL) != 1) {
    fprintf(stderr, "Error loading CA certificates.\n");
    close(client_socket_tc);
    SSL_CTX_free(ssl_ctx_tc);
    exit(EXIT_FAILURE);
}
    // Step 5: Configure SSL Context for the Client
    SSL_CTX_set_verify(ssl_ctx_tc, SSL_VERIFY_PEER, NULL);
    //bob certs verified
    // Set up verification callback function
    SSL_CTX_set_verify_depth(ssl_ctx_tc, 2); // Adjust verification depth if needed

    // Configure SSL context options
    SSL_CTX_set_options(ssl_ctx_tc, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);


    // Step 6: Connect to the Server

    // Step 7: Set up DTLS connection
    SSL *ssl_tc = SSL_new(ssl_ctx_tc);

    SSL_set_fd(ssl_tc,client_socket_tc);
    // Perform the DTLS handshake
    if (SSL_connect(ssl_tc) != 1) {
        fprintf(stderr, "Error performing DTLS handshake.\n");
        close(client_socket_tc);
        SSL_CTX_free(ssl_ctx_tc);
        exit(EXIT_FAILURE);
    }



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
        char reply[MAX_BUF_SIZE];
        int yes=0;
        int len;

        // Receive messages from the client
        while ((len = SSL_read(ssl, buffer, MAX_BUF_SIZE)) > 0) {
            // Null-terminate the received message
            buffer[len] = '\0';

            // Display the received message
            std::cout << "Client has sent this: " << buffer << std::endl;
            //if client's response is exit then close the connection-working
  






    //memset(buffer, 0, sizeof(buffer));
    //std::cout << "What to Send to server: ";
    // std::cin.getline(buffer, MAX_BUF_SIZE);



    // Send the message to the server
    
    if (SSL_write(ssl_tc, buffer, strlen(buffer)) <= 0) {
        // Error occurred during SSL_write
        int ssl_error_tc = SSL_get_error(ssl_tc, -1);
        if (ssl_error_tc == SSL_ERROR_WANT_READ || ssl_error_tc == SSL_ERROR_WANT_WRITE) {
                  // No data available for writing, continue waiting
            continue;


        } else {
            // Other error occurred, handle accordingly
            std::cerr << "Error occurred during SSL_write." << std::endl;
            break;
        }
    }





    // Receive a message from the server
    int len = SSL_read(ssl_tc, buffer, MAX_BUF_SIZE);
    if (len > 0) {
        buffer[len] = '\0'; // Null-terminate the received message
        std::cout << "Server has sent this: " << buffer << std::endl; // Print the received message

        //if server's response is exit then close the connection
        {


        }
    }





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
        // Step 9: Clean up SSL resources
    SSL_free(ssl_tc);
    SSL_CTX_free(ssl_ctx_tc);
    close(client_socket_tc);
    }


    int main( int argc, char* argv[]){

        

    // Check for correct command-line argument syntax
    if (argc != 4 || std::string(argv[1]) != "-m") {
        std::cerr << "Usage: " << argv[0] << " -m <client_hostname> <server_hostname>" << std::endl;
        exit(EXIT_FAILURE);
    }


    std::string server_hostname = argv[3]; // Server hostname from command line
    struct hostent* host_server = gethostbyname(server_hostname.c_str());
    if (host_server == NULL) {
        std::cerr << "Failed to find the server hostname: " << server_hostname << std::endl;
        exit(EXIT_FAILURE);
    }
    char* server_ip = inet_ntoa(*reinterpret_cast<struct in_addr*>(host_server->h_addr));
    std::cout << "Resolved Server IP: " << server_ip << std::endl;


            initialize_openssl();
        handle_server_mode();
    cleanup_openssl();

    

            initialize_openssl();
        handle_server_mode();
    cleanup_openssl();

    }






//if you want to tamper messages then remove comment from 444 445 and 446
   

