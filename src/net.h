//
// Created by biprarshi on 21/03/2026.
//

#ifndef CLINK_NET_H
#define CLINK_NET_H

#include <stdint.h>
#include <sys/socket.h>   // socket(), bind(), listen(), accept(), connect()
#include <netinet/in.h>   // struct sockaddr_in, INADDR_ANY
#include <arpa/inet.h>    // inet_pton() — converts "192.168.1.1" string to binary
#include <unistd.h>       // close(), read(), write()

int net_listen(int port); // server: returns connected fd
int net_connect(const char *ip, int port); // client: returns connected fd
int net_send(int fd, const uint8_t *data, uint32_t len);
int net_recv(int fd, uint8_t **data, uint32_t *len); // allocates buffer
void net_close(int fd);

#endif //CLINK_NET_H