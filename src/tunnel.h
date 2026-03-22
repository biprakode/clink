//
// Created by biprarshi on 22/03/2026.
//

#ifndef CLINK_TUNNEL_H
#define CLINK_TUNNEL_H
#include <stdint.h>

typedef struct {
    int fd; // network connection
    uint8_t key[32]; // AES key
    uint8_t iv[16]; // IV
    uint64_t counter; // incremented per message for unique nonce
    uint64_t send_ctr; // incremented every send
    uint64_t recv_ctr; // incremented every recv
} Tunnel;

int tunnel_handshake_server(Tunnel *t , int fd);
int tunnel_handshake_client(Tunnel *t , int fd);
int tunnel_send(Tunnel *t, const uint8_t *plaintext, uint32_t len);
int tunnel_recv(Tunnel *t, uint8_t **plaintext, uint32_t *len);

#endif //CLINK_TUNNEL_H