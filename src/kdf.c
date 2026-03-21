//
// Created by biprarshi on 21/03/2026.
//
#include "kdf.h"

#include <stdlib.h>
#include <string.h>

#include "sha256.h"

void kdf(const BigNum *shared_secret, uint8_t key_out[32], uint8_t iv_out[16]) {
    size_t secret_len;
    uint8_t *secret_bytes = bignum_to_bytes(shared_secret, &secret_len);
    sha256(secret_bytes, secret_len, key_out);

    uint8_t buffer[secret_len + 1];
    memcpy(buffer, secret_bytes, secret_len);
    buffer[secret_len] = 0x01;

    uint8_t iv_buff[32];
    sha256(buffer, secret_len + 1, iv_buff);
    memcpy(iv_out , iv_buff , 16);


    free(secret_bytes);
}
