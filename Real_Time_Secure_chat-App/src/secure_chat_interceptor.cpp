#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#define MAX_BUF_SIZE 1024
#define SERVER_PORT 45678

#include <sys/poll.h>
#include <cstring>   //For strlen()
#include <unistd.h> //For close()

#include <openssl/err.h>
#include <openssl/rand.h>
//added later for getting the ip address
#include <netdb.h>
#include <netinet/in.h>





int main(int argc, char* argv[]) {

    // Check for correct command-line argument syntax
    if (argc != 4 || std::string(argv[1]) != "-d") {
        std::cerr << "Usage: " << argv[0] << " -d <client_hostname> <server_hostname>" << std::endl;
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

    // Step 2: Create a UDP Socket and Bind it to a Port
    int server_fd = socket(AF_INET, SOCK_DGRAM, 0); // Use AF_INET for IPv4
    if (server_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    server_addr.sin_addr.s_addr = inet_addr("172.31.0.4");
    //server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Set to loopback address //set to 172.31.0.4
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
const char * CHAT_OK_REPLY= "chat_ok_reply";
    const char * not_Supported="chat_START_SSL_not_Supported";

    // trudy server

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
    printf("Message from client: %s\n", buffer);//on server side

    ssize_t valsent = sendto(server_fd, CHAT_OK_REPLY, strlen(CHAT_OK_REPLY), 0,
                            (const struct sockaddr *)&client_addr, sizeof(client_addr));
    if (valsent == -1) {
        perror("sendto");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
  // trudy server


const char * CHAT_HELLO="chat_hello";



    std::string ip_address = server_ip;
    const char* start_ssl = "chat_START_SSL";
    const char* start_normal = "chat_START_NORMAL";
    struct sockaddr_in c_address;

      c_address.sin_port = htons(SERVER_PORT);
    c_address.sin_family = AF_INET;
    int add_len = sizeof(c_address);
    c_address.sin_addr.s_addr = inet_addr(server_ip); //solve using dns resolving

    memset(&(c_address.sin_zero), '\0', 8);
    int client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);


    if (client_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (connect(client_socket, (struct sockaddr *)&c_address, sizeof(c_address)) == -1) {
        perror("connect");
        close(client_socket);
        //SSL_CTX_free(ssl_ctx);
        exit(EXIT_FAILURE);
    }

    // Send data to server
    memset(buffer, 0, sizeof(buffer));
    ssize_t val_sent = sendto(client_socket, CHAT_HELLO, strlen(CHAT_HELLO), 0,
                            (const struct sockaddr *)&c_address, sizeof(c_address));
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


printf("Received %zd bytes from server\n", val_read);
printf("Message from server: %s\n", buffer);
    if (client_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

// Clean the buffer
memset(buffer, 0, sizeof(buffer));


// trudy client


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

//send ssl_not_supported to client

    ssize_t valuesent = sendto(server_fd,not_Supported , strlen(not_Supported), 0,
                            (const struct sockaddr *)&client_addr, sizeof(client_addr));
if (valuesent == -1) {
    perror("sendto");
    close(server_fd);
    exit(EXIT_FAILURE);
}


// Send "start_normal" message to server
ssize_t value_sent = sendto(client_socket, start_normal, strlen(start_normal), 0,
                            (const struct sockaddr *)&c_address, sizeof(c_address));
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
printf("Message from server/see: %s\n", buffer);
  if (client_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
int flag=0;



// recive and forward messeges



memset(buffer, 0, sizeof(buffer));

int BUFFER_SIZE=sizeof(buffer);



    while (true) {
        int leng, n;
        leng = sizeof(client_addr);

        // Receive message from client
        n = recvfrom(server_fd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, (socklen_t *)&leng);
        buffer[n] = '\0';


        // Display the message received from client
        std::cout << "Client: " << buffer << std::endl;


         // Send message to server
        sendto(client_socket, buffer, strlen(buffer), 0, (const struct sockaddr *)&c_address, sizeof(c_address));

        socklen_t len;
        len = sizeof(c_address);

        // Receive msg from server
        n = recvfrom(client_socket, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&c_address, &len);



        // Display msg received from server
        std::cout << "Server: " << buffer << std::endl;

        // forward to the client
        sendto(server_fd, buffer, strlen(buffer), 0, (const struct sockaddr *)&client_addr, leng);





          buffer[n] = '\0';
    }



}
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
