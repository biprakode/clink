//
// Created by biprarshi on 21/03/2026.
//

#ifndef CLINK_KDF_H
#define CLINK_KDF_H

#include "bignum.h"
void kdf(const BigNum *shared_secret, uint8_t key_out[32], uint8_t iv_out[16]);

#endif //CLINK_KDF_H