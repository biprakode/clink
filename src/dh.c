//
// Created by biprarshi on 20/03/2026.
//

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "dh.h"
#include "bignum.h"

static void read_urandom(uint8_t *buf , int len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("open /dev/urandom"); return; }
    read(fd, buf, len);
    close(fd);
}

void generate_private_key(BigNum *x , const BigNum *p) {
    BigNum upper , two;
    memset(upper.limbs, 0, sizeof(upper.limbs));
    upper.size = 1;
    memset(two.limbs, 0, sizeof(two.limbs));
    two.size = 1;
    two.limbs[0] = 2;

    BigNum p_two;
    bignum_copy(&p_two , p);
    bignum_sub(&upper , &p_two , &two);

    do {
        uint8_t raw[32];
        read_urandom(raw, 32);
        bignum_from_bytes(x , raw , 32);
    } while (bignum_cmp(x , &two) < 0 || bignum_cmp(x , &upper) > 0);
}

void dh_init(DH_CTX *ctx) {
    bignum_from_hex(&ctx->prime , prime);
    bignum_from_hex(&ctx->gen , gen);

    barrett_precompute(&ctx->barrett_ctx , &ctx->prime);
    generate_private_key(&ctx->pri, &ctx->prime);
    mod_exp_barrett(&ctx->pub , &ctx->gen , &ctx->pri , &ctx->barrett_ctx); //public key X = g^x mod p
}

void dh_get_public(DH_CTX *ctx , BigNum *pub) {
    pub = &ctx->pub;
}

void dh_compute_shared(DH_CTX *ctx , BigNum *their_pub , BigNum *shared) {
    mod_exp_barrett(shared , their_pub , &ctx->pri , &ctx->barrett_ctx); // shared = their_X ^ our_x mod p = g^(ab) mod p
}
