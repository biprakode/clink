//
// Created by biprarshi on 21/03/2026.
//

#include "net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>        // close(), read(), write()
#include <sys/socket.h>    // socket(), bind(), listen(), accept(), connect()
#include <netinet/in.h>    // struct sockaddr_in, INADDR_ANY, htons()
#include <arpa/inet.h>     // inet_pton() — converts IP string to binary

// write exactly `len` bytes to fd, looping because write() can send partial data
static int write_all(int fd, const uint8_t *data, uint32_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, data + sent, len - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

// read exactly `len` bytes from fd, looping because read() can return partial data
static int read_all(int fd, uint8_t *data, uint32_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = read(fd, data + received, len - received);
        if (n <= 0) return -1;
        received += n;
    }
    return 0;
}

// server: create socket, bind to port, wait for one client, return connected fd
int net_listen(int port) {
    // create TCP socket (AF_INET = IPv4, SOCK_STREAM = TCP)
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return -1; }

    // allow port reuse so restarting doesn't get "address already in use"
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // bind socket to port on all interfaces
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;    // listen on all network interfaces
    addr.sin_port = htons(port);          // convert port to network byte order

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    // start listening — backlog of 1, we only need one client
    if (listen(sockfd, 1) < 0) {
        perror("listen");
        close(sockfd);
        return -1;
    }

    printf("[net] listening on port %d...\n", port);

    // accept() blocks until a client connects, returns a new fd for that connection
    int client_fd = accept(sockfd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        close(sockfd);
        return -1;
    }

    // done listening — close the listening socket, talk through client_fd
    close(sockfd);
    printf("[net] client connected\n");
    return client_fd;
}

// client: connect to server at ip:port, return connected fd
int net_connect(const char *ip, int port) {
    // create TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return -1; }

    // set up server address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // inet_pton: convert IP string "127.0.0.1" to binary format
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return -1;
    }

    // connect() does the TCP handshake (SYN -> SYN-ACK -> ACK)
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    printf("[net] connected to %s:%d\n", ip, port);
    return sockfd;
}

// send a length-prefixed message: [4-byte big-endian length][payload]
int net_send(int fd, const uint8_t *data, uint32_t len) {
    // write 4-byte header so receiver knows how many bytes to expect
    uint8_t header[4];
    header[0] = (uint8_t)(len >> 24);
    header[1] = (uint8_t)(len >> 16);
    header[2] = (uint8_t)(len >> 8);
    header[3] = (uint8_t)(len);

    if (write_all(fd, header, 4) < 0) return -1;
    if (write_all(fd, data, len) < 0) return -1;
    return 0;
}

// receive a length-prefixed message — allocates buffer, caller must free()
int net_recv(int fd, uint8_t **data, uint32_t *len) {
    // read the 4-byte length header
    uint8_t header[4];
    if (read_all(fd, header, 4) < 0) return -1;

    // reconstruct length from big-endian bytes
    *len = ((uint32_t)header[0] << 24) |
           ((uint32_t)header[1] << 16) |
           ((uint32_t)header[2] << 8)  |
           ((uint32_t)header[3]);

    // allocate buffer and read exactly that many bytes of payload
    *data = (uint8_t *)malloc(*len);
    if (read_all(fd, *data, *len) < 0) {
        free(*data);
        *data = NULL;
        return -1;
    }
    return 0;
}

// close a connection
void net_close(int fd) {
    close(fd);
}
