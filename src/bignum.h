//
// Created by biprarshi on 18/03/2026.
//

#ifndef CLINK_BIGNUM_H
#define CLINK_BIGNUM_H
#include <sys/types.h>

typedef struct {
    u_int64_t limbs[16];
    int size;
} BigNum;


void bignum_add(BigNum * r , const BigNum * a, const BigNum * b);
void bignum_sub(BigNum * r , const BigNum * a, const BigNum * b);
void bignum_mul(BigNum * r , const BigNum * a, const BigNum * b);
int bignum_cmp(const BigNum * a, const BigNum * b);
void bignum_mod(BigNum * r , const BigNum * a, const BigNum * m);
void bignum_from_hex(BigNum *r , const char * hex);
void bignum_to_hex(const BigNum * r, char * hex);


#endif //CLINK_BIGNUM_H