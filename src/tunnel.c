//
// Created by biprarshi on 22/03/2026.
//

#include "tunnel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "bignum.h"
#include "net.h"
#include "dh.h"
#include "kdf.h"

int tunnel_handshake_server(Tunnel *t , int fd) {

    // step 1: receive client's DH public key (server waits first)
    uint8_t *their_pk_bytes;
    uint32_t their_pk_len;
    if (net_recv(fd , &their_pk_bytes , &their_pk_len) < 0) {
        fprintf(stderr , "[tunnel] failed to receive client public key\n");
        return -1;
    }

    // step 2: convert raw bytes into BigNum for DH math
    BigNum their_pub;
    bignum_from_bytes(&their_pub , their_pk_bytes , their_pk_len);

    // wipe and free
    memset(their_pk_bytes , 0 , their_pk_len);
    free(their_pk_bytes);

    // step 3: generate our own DH keypair (private x, public g^x mod p)
    DH_CTX dh_ctx;
    dh_init(&dh_ctx);

    // step 4: send our public key to the client
    size_t my_pk_len;
    uint8_t *my_pk_bytes = bignum_to_bytes(&dh_ctx.pub , &my_pk_len);
    if (net_send(fd , my_pk_bytes , my_pk_len) < 0) {
        fprintf(stderr , "[tunnel] failed to send server public key\n");
        memset(my_pk_bytes , 0 , my_pk_len);
        free(my_pk_bytes);
        return -1;
    }
    memset(my_pk_bytes , 0 , my_pk_len);
    free(my_pk_bytes);

    // step 5: compute shared secret = their_pub^our_private mod p
    BigNum shared;
    dh_compute_shared(&dh_ctx , &their_pub , &shared);

    // step 6: derive AES key (32 bytes) and IV (16 bytes) from shared secret
    kdf(&shared , t->key , t->iv);

    // step 7: initialize tunnel state
    t->fd = fd;
    t->send_ctr = 0;
    t->recv_ctr = 0;

    // wipe the shared secret
    memset(&shared , 0 , sizeof(shared));
    // wipe private key to
    memset(&dh_ctx.pri , 0 , sizeof(dh_ctx.pri));

    printf("[tunnel] server handshake complete\n");
    return 0;
}

int tunnel_handshake_client(Tunnel *t , int fd) {
    // step 1: generate our DH keypair (client goes first)
    DH_CTX dh_ctx;
    dh_init(&dh_ctx);

    // step 2: send our public key to the server
    size_t my_pk_len;
    uint8_t *my_pk_bytes = bignum_to_bytes(&dh_ctx.pub , &my_pk_len);
    if (net_send(fd , my_pk_bytes , my_pk_len) < 0) {
        fprintf(stderr , "[tunnel] failed to send client public key\n");
        memset(my_pk_bytes , 0 , my_pk_len);
        free(my_pk_bytes);
        return -1;
    }
    memset(my_pk_bytes , 0 , my_pk_len);
    free(my_pk_bytes);

    // step 3: receive server's public key
    uint8_t *their_pk_bytes;
    uint32_t their_pk_len;
    if (net_recv(fd , &their_pk_bytes , &their_pk_len) < 0) {
        fprintf(stderr , "[tunnel] failed to receive server public key\n");
        return -1;
    }

    // step 4: convert raw bytes into BigNum for DH math
    BigNum their_pub;
    bignum_from_bytes(&their_pub , their_pk_bytes , their_pk_len);

    // wipe and free received key bytes
    memset(their_pk_bytes , 0 , their_pk_len);
    free(their_pk_bytes);

    // step 5: compute shared secret = their_pub^our_private mod p
    BigNum shared;
    dh_compute_shared(&dh_ctx , &their_pub , &shared);

    // step 6: derive AES key (32 bytes) and IV (16 bytes) from shared secret
    kdf(&shared , t->key , t->iv);

    // step 7: initialize tunnel state
    t->fd = fd;
    t->send_ctr = 0;
    t->recv_ctr = 0;

    // wipe the shared secret
    memset(&shared , 0 , sizeof(shared));
    // wipe private key too
    memset(&dh_ctx.pri , 0 , sizeof(dh_ctx.pri));

    printf("[tunnel] client handshake complete\n");
    return 0;
}

int tunnel_send(Tunnel *t, const uint8_t *plaintext, uint32_t len) {
    // build unique nonce: iv XOR send_ctr
    uint8_t nonce[16];
    memcpy(nonce , t->iv , 16);
    nonce[8]  ^= (uint8_t) (t->send_ctr >> 56);
    nonce[9]  ^= (uint8_t) (t->send_ctr >> 48);
    nonce[10] ^= (uint8_t) (t->send_ctr >> 40);
    nonce[11] ^= (uint8_t) (t->send_ctr >> 32);
    nonce[12] ^= (uint8_t) (t->send_ctr >> 24);
    nonce[13] ^= (uint8_t) (t->send_ctr >> 16);
    nonce[14] ^= (uint8_t) (t->send_ctr >> 8);
    nonce[15] ^= (uint8_t) (t->send_ctr);

    // encrypt into separate buffer — plaintext is const, can't write into it
    uint8_t ciphertext[len];
    aes256_ctr(t->key , nonce , plaintext , ciphertext , len);
    if (net_send(t->fd , ciphertext , len) < 0) {
        fprintf(stderr , "[tunnel] failed to send ciphertext\n");
        return -1;
    }

    t->send_ctr++;
    return 0;
}

int tunnel_recv(Tunnel *t, uint8_t **plaintext, uint32_t *len) {
    // net_recv mallocs a buffer and fills it with the ciphertext
    if (net_recv(t->fd , plaintext , len) < 0) {
        fprintf(stderr , "[tunnel] failed to receive ciphertext\n");
        return -1;
    }

    // build nonce: iv XOR recv_ctr
    uint8_t nonce[16];
    memcpy(nonce , t->iv , 16);
    nonce[8]  ^= (uint8_t) (t->recv_ctr >> 56);
    nonce[9]  ^= (uint8_t) (t->recv_ctr >> 48);
    nonce[10] ^= (uint8_t) (t->recv_ctr >> 40);
    nonce[11] ^= (uint8_t) (t->recv_ctr >> 32);
    nonce[12] ^= (uint8_t) (t->recv_ctr >> 24);
    nonce[13] ^= (uint8_t) (t->recv_ctr >> 16);
    nonce[14] ^= (uint8_t) (t->recv_ctr >> 8);
    nonce[15] ^= (uint8_t) (t->recv_ctr);

    // decrypt in place — CTR mode is just XOR with keystream
    aes256_ctr(t->key , nonce , *plaintext , *plaintext , *len);

    t->recv_ctr++;
    return 0;
}
