//
// Created by biprarshi on 18/03/2026.
//

#ifndef CLINK_BIGNUM_H
#define CLINK_BIGNUM_H
#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_LIMBS 128

typedef struct {
    uint64_t limbs[MAX_LIMBS];
    int size;
} BigNum;

typedef struct {
    BigNum m;   // Modulus
    BigNum mu;  // Precomputed value
    int k;      // Bit length or parameter for reduction
} BarrettCtx;

/* --- Utility & Management --- */
void bignum_trim(BigNum *r);
void bignum_copy(BigNum *r, const BigNum *a);
void bignum_from_hex(BigNum *r, const char *hex);
void bignum_to_hex(const BigNum *r, char *hex);
void bignum_print(const BigNum *r);
void bignum_from_bytes(BigNum *r , const uint8_t *raw , int len);
uint8_t *bignum_to_bytes(const BigNum * r, size_t *len);

/* --- Comparison & Information --- */
int bignum_cmp(const BigNum *a, const BigNum *b);
int bignum_bit_set(const BigNum *r, int bit_index);
int bignum_bit_len(BigNum *r);

/* --- Basic Arithmetic --- */
void bignum_add(BigNum *r, const BigNum *a, const BigNum *b);
void bignum_sub(BigNum *r, const BigNum *a, const BigNum *b);
void bignum_mul(BigNum *r, const BigNum *a, const BigNum *b);
void bignum_div(BigNum *q, BigNum *r, BigNum *a, BigNum *b);

/* --- Bitwise Shifts --- */
void bignum_lshift(BigNum *a, int n);
void bignum_rshift(BigNum *a, int n);
void bignum_shl(BigNum *r, BigNum *a, int n); // Shift left with copy
void bignum_shr(BigNum *r, BigNum *a, int n); // Shift right with copy

/* --- Modular Operations --- */
void bignum_mod(BigNum *r, const BigNum *a, const BigNum *b);
void modexp(BigNum *r, const BigNum *a, BigNum *b, const BigNum *m);

/* --- Barrett Reduction --- */
void barrett_precompute(BarrettCtx *ctx, BigNum *m);
void bignum_barrett_mod(BigNum *r, BigNum *a, const BarrettCtx *ctx);
void mod_exp_barrett(BigNum *r, BigNum *base, BigNum *exp, BarrettCtx *ctx);


#endif //CLINK_BIGNUM_H