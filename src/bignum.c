#include "bignum.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

# define MAX_LIMBS 16

void bignum_trim(BigNum *r) {
    while (r->size > 1 && r->limbs[r->size - 1] == 0)
        r->size--;
}

void bignum_copy(BigNum * r , const BigNum * a) {
    r->size = a->size;
    for (int i = 0 ; i < a->size ; i++) {
        r->limbs[i] = a->limbs[i];
    }
}

void bignum_add(BigNum * r , const BigNum * a, const BigNum * b) {
    const int max_size = a->size > b->size ? a->size : b->size;
    r->size = max_size;
    u_int64_t carry = 0;
    for (int i = 0; i < max_size; i++) {
        uint64_t sum = a->limbs[i] + b->limbs[i] + carry;
        carry = (sum < a->limbs[i]) ? 1 : 0;  // overflow detected
        r->limbs[i] = sum;
    }
    if (carry) {
        r->limbs[max_size] = 1;
        r->size++;
    }
    bignum_trim(r);
}

void bignum_sub(BigNum * r , const BigNum * a, const BigNum * b) {
    const int max_size = a->size > b->size ? a->size : b->size;
    r->size = max_size;
    int borrow = 0;
    for (int i = 0; i < max_size; i++) {
        uint64_t bi = (i < b->size) ? b->limbs[i] : 0;
        uint64_t sub = a->limbs[i] - bi - borrow;
        borrow = (a->limbs[i] < bi + borrow) ? 1 : 0;
        r->limbs[i] = sub;
    }
    bignum_trim(r);
}

void bignum_mul(BigNum * r , const BigNum * a, const BigNum * b) {
    if (a->size + b->size > MAX_LIMBS) {
        printf("Overflow Error");
        return;
    }

    memset(r->limbs, 0, sizeof(r->limbs));

    int max_size = a->size + b->size;
    r->size = max_size;

    for (int i = 0 ; i<a->size ; i++) {
        uint64_t carry = 0;
        for (int j = 0 ; j < b->size ; j++) {
            __uint128_t wide = (__uint128_t)a->limbs[i] * (__uint128_t)b->limbs[j] + r->limbs[i+j] + carry;
            r->limbs[i+j] = (u_int64_t)wide;
            carry = (u_int64_t)(wide >> 64);
        }
        r->limbs[i+b->size] += carry;
    }
    bignum_trim(r);
}

int bignum_cmp(const BigNum * a, const BigNum * b) {
    if ( a->size != b->size ) {
        return a->size < b->size ? -1 : 1;
    }
    for (int i = a->size - 1; i >= 0; i--) {
        if (a->limbs[i] > b->limbs[i]) return 1;
        if (a->limbs[i] < b->limbs[i]) return -1;
    }
    return 0;
}

void bignum_from_hex(BigNum *r , const char * hex) {
    int len = strlen(hex);
    r->size = 0;
    for (int i = len ; i > 0 && r->size < 16 ; i-=16) {
        int start = (i - 16 < 0) ? 0 : i-16;
        int chunk = i - start;
        char buf[17] = {0};
        memccpy(buf , hex + start, chunk, 16);
        char *end;
        r->limbs[r->size++] = (u_int64_t)strtoull(buf, &end, 16);
        if (end == hex) {
            printf("String error");
            return;
        }else {
            printf("Conversation failed at - %s\n"  , end);
        }
    }
}

void bignum_to_hex(const BigNum * r, char * hex) {
    size_t total_size = r->size * 16 + 1;

    hex[0] = '\0';
    for (int i = r->size - 1; i >= 0; i--) {
        char buffer[17];
        snprintf(buffer , sizeof(buffer) , "%016" PRIx64, r->limbs[i]);
        strcat(hex, buffer);
    }
}

void bignum_print(const BigNum *r) {
    char buffer[17];
    printf("0x");
    for (int i = r->size - 1; i >= 0; i--) {
        snprintf(buffer , sizeof(buffer) , "%016" PRIx64, r->limbs[i]);
        printf("%s\n", buffer);
    }
}

void bignum_lshift(BigNum *a, int n) {
    if (n <= 0) return;

    uint64_t carry = 0;
    for (int i = 0; i < a->size; i++) {
        uint64_t next_carry = a->limbs[i] >> (64 - n);
        a->limbs[i] = (a->limbs[i] << n) | carry;
        carry = next_carry;
    }

    // If there is a remaining carry, the number grows by one limb
    if (carry) {
        a->limbs[a->size] = carry;
        a->size++;
    }
}

void bignum_rshift(BigNum *a, int n) {
    if (n <= 0 || a->size == 0) return;

    uint64_t carry = 0;
    for (int i = a->size - 1; i >= 0; i--) {
        uint64_t next_carry = a->limbs[i] << (64 - n);
        a->limbs[i] = (a->limbs[i] >> n) | carry;
        carry = next_carry;
    }

    // Shrink size if the top limbs are now zero
    while (a->size > 0 && a->limbs[a->size - 1] == 0) {
        a->size--;
    }
}


void bignum_shr(BigNum *r , BigNum *a , int n) {
    bignum_copy(r , a);
    int limb_shift = n/64;
    int bit_shift = n%64;

    if (limb_shift) {
        for (int i = 0 ; i<r->size - limb_shift; i++) {
            r->limbs[i] = r->limbs[limb_shift+i];
        }
        for (int i = r->size - limb_shift; i<r->size; i++) {
            r->limbs[i] = 0;
        }
        r->size = (r->size > limb_shift) ? r->size - limb_shift : 1;
    }

    if (bit_shift) {
        bignum_rshift(r , bit_shift);
    }
    bignum_trim(r);
}

void bignum_shl(BigNum *r , BigNum *a , int n) {
    bignum_copy(r , a);
    int limb_shift = n/64;
    int bit_shift = n%64;
    if (limb_shift) {
        for (int i = r->size - 1; i >= 0; i--) {
            r->limbs[i + limb_shift] = r->limbs[i];
        }
        for (int i = 0; i < limb_shift; i++) {
            r->limbs[i] = 0;
        }
        r->size = r->size + limb_shift;
    }
    if (bit_shift) {
        bignum_lshift(r , bit_shift);
    }
}

int bignum_bit_set(const BigNum * r, int bit_index) {
    int bit_len = bit_index / 64;
    int bit_offset = bit_index % 64;
    if (bit_len > r->size) return -1;
    return r->limbs[bit_len] >> bit_offset & 1;
}

int bignum_bit_len(BigNum * r) {
    bignum_trim(r);
    if (r->size == 0) return 0;
    int bits = r->size * 64;
    uint64_t last_limb = r->limbs[r->size - 1];
    while (last_limb == 0 && bits > 0) { bits--; }
    if (last_limb == 0) return 0;
    return (r->size - 1) * 64 + (64 - __builtin_clzll(last_limb));
}

void modexp(BigNum *r, const BigNum *base, BigNum *exp, const BigNum *m) {
    BigNum res , temp;
    memset(res.limbs, 0, sizeof(res.limbs));
    res.limbs[0] = 1;
    res.size = 1;

    int total_bits = bignum_bit_len(exp);
    for (int i = total_bits - 1; i >= 0; i--) {
        bignum_mul(&temp, &res, &res);      // temp = res^2
        bignum_mod(&res, &temp, m);         // res  = temp mod m

        if (bignum_bit_set(exp, i)) {
            bignum_mul(&temp, &res, base);  // temp = res * base
            bignum_mod(&res, &temp, m);     // res  = temp mod m
        }
    }
    bignum_copy(r, &res);
}

void bignum_div(BigNum *q , BigNum *r , BigNum *a , BigNum *b) {
    memset(q->limbs, 0, sizeof(q->limbs));
    q->size = 1;
    memset(r->limbs, 0, sizeof(r->limbs));
    r->size = 1;

    int total_bits = bignum_bit_len(a);
    for (int i = total_bits - 1; i >= 0; i--) {
        // rem = rem << 1
        bignum_lshift(r , 1);

        // copy bit i of a into LSB of rem
        if (bignum_bit_set(a , i)) {
            r->limbs[0] |= 1;
        }

        // if rem >= b: rem -= b, set bit i of quotient
        if (bignum_cmp(r, b) >= 0) {
            bignum_sub(r, r, b);
            int li = i / 64;
            int bi = i % 64;
            q->limbs[li] |= (uint64_t)1 << bi;
            if (li + 1 > q->size) q->size = li + 1;
        }
    }
    bignum_trim(r);
    bignum_trim(q);
}

void barrett_precompute(BarrettCtx *ctx, BigNum *m) {
    bignum_copy(&ctx->m , m);
    ctx->k = bignum_bit_len(m);

    // build 2^(2k) — just the number 1 shifted left by 2k bits
    BigNum power;
    memset(power.limbs, 0, sizeof(power.limbs));
    power.limbs[0] = 1;
    power.size = 1;
    bignum_shl(&power, &power, 2 * ctx->k);

    BigNum rem;
    bignum_div(&ctx->mu , &rem , &power, m);
}

void bignum_barrett_mod(BigNum *r , BigNum *a , const BarrettCtx *ctx) {
    if (bignum_cmp(a , &ctx->m) == -1) {
        bignum_copy(r , a);
        return;
    }

    int k = ctx->k;
    //q1 = floor(a / 2^(k-1))
    BigNum q1;
    bignum_shr(&q1, a, k - 1);

    //q2 = q1 * mu = a * 2^(k+1) / m
    BigNum q2;
    bignum_mul(&q2, &q1, &ctx->mu);

    //q3 = floor(q2 / 2^(k+1)) = floor(a / m)
    BigNum q3;
    bignum_shr(&q3, &q2, k + 1);

    //r = a - q3 * m
    BigNum q3m;
    bignum_mul(&q3m, &q3, &ctx->m);
    bignum_sub(r, a, &q3m);

    int corrections = 0;
    while (bignum_cmp(r, &ctx->m) >= 0) {
        bignum_sub(r, r, &ctx->m);
        corrections++;
        if (corrections > 2) {
            printf("barrett_mod: correction overflow\n");
            break;
        }
    }
}


void mod_exp_barrett(BigNum *r , BigNum *base , BigNum *exp , BarrettCtx *ctx) {
    BigNum res;
    memset(res.limbs, 0, sizeof(res.limbs));
    res.limbs[0] = 1;
    res.size = 1;

    int total_bits = bignum_bit_len((BigNum *)exp);
    for (int i = total_bits - 1; i >= 0; i--) {
        BigNum temp;
        bignum_mul(&temp, &res, &res);
        bignum_barrett_mod(&res, &temp, ctx);
        if (bignum_bit_set(exp , i)) {
            bignum_mul(&temp, &res, base);
            bignum_barrett_mod(&res, &temp, ctx);
        }
    }
    bignum_copy(r , &res);
}

void bignum_mod(BigNum * r , const BigNum * a, const BigNum * b) {
    if ( bignum_cmp(a , b) == -1) {
        bignum_copy(r , a);
        return;
    }
    bignum_copy(r , a);
    BigNum current_b;
    bignum_copy(&current_b , b);

    // shift current_b left until its just about to exceed r
    int shift_count = 0;
    while (bignum_cmp(&current_b, r) <= 0) {
        bignum_lshift(&current_b , 1);
        shift_count++;
    }

    // shifted one too many times in the loop above
    bignum_rshift(&current_b , 1);
    shift_count--;

    for (int i = 0; i <= shift_count; i++) {
        if (bignum_cmp(r, &current_b) >= 0) {
            bignum_sub(r, r, &current_b); // r = r - current_b
        }
        bignum_rshift(&current_b , 1); // Shift current_b back right
    }
}

