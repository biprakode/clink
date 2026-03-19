#include <stdio.h>
#include <string.h>
#include "bignum.h"

// ── test harness ──────────────────────────────────────────────
static int tests_run    = 0;
static int tests_passed = 0;

#define PASS(name) do { tests_run++; tests_passed++; \
    printf("  PASS  %s\n", name); } while(0)
#define FAIL(name, ...) do { tests_run++; \
    printf("  FAIL  %s — ", name); printf(__VA_ARGS__); printf("\n"); } while(0)

// compare r's hex output to an expected hex string
static int check_hex(const BigNum *r, const char *expected, const char *test) {
    char buf[1024] = {0};
    bignum_to_hex(r, buf);
    if (strcmp(buf, expected) == 0) {
        PASS(test);
        return 1;
    } else {
        FAIL(test, "got %s  want %s", buf, expected);
        return 0;
    }
}

// ── addition tests ────────────────────────────────────────────
void test_add() {
    printf("\n[add]\n");
    BigNum a, b, r;

    // 1 + 1 = 2
    a = (BigNum){ .limbs = {1}, .size = 1 };
    b = (BigNum){ .limbs = {1}, .size = 1 };
    bignum_add(&r, &a, &b);
    check_hex(&r, "0000000000000002", "1 + 1 = 2");

    // carry across limb boundary: 0xFFFFFFFFFFFFFFFF + 1 = 1_0000000000000000
    a = (BigNum){ .limbs = {0xFFFFFFFFFFFFFFFF}, .size = 1 };
    b = (BigNum){ .limbs = {1},                  .size = 1 };
    bignum_add(&r, &a, &b);
    // expected: limbs[1]=1, limbs[0]=0 → hex "00000000000000010000000000000000"
    check_hex(&r, "00000000000000010000000000000000", "0xFFFF...+1 carry");

    // different sizes: 0 + large
    a = (BigNum){ .limbs = {0}, .size = 1 };
    b = (BigNum){ .limbs = {0xDEADBEEFCAFEBABE, 0x1}, .size = 2 };
    bignum_add(&r, &a, &b);
    check_hex(&r, "0000000000000001deadbeefcafebabe", "0 + 2-limb");
}

// ── subtraction tests ─────────────────────────────────────────
void test_sub() {
    printf("\n[sub]\n");
    BigNum a, b, r;

    // 5 - 3 = 2
    a = (BigNum){ .limbs = {5}, .size = 1 };
    b = (BigNum){ .limbs = {3}, .size = 1 };
    bignum_sub(&r, &a, &b);
    check_hex(&r, "0000000000000002", "5 - 3 = 2");

    // borrow across limb: 0x1_0000000000000000 - 1
    a = (BigNum){ .limbs = {0, 1}, .size = 2 };
    b = (BigNum){ .limbs = {1},    .size = 1 };
    bignum_sub(&r, &a, &b);
    check_hex(&r, "ffffffffffffffff", "borrow across limb");
}

// ── multiplication tests ──────────────────────────────────────
void test_mul() {
    printf("\n[mul]\n");
    BigNum a, b, r;

    // 3 * 5 = 15
    a = (BigNum){ .limbs = {3}, .size = 1 };
    b = (BigNum){ .limbs = {5}, .size = 1 };
    bignum_mul(&r, &a, &b);
    check_hex(&r, "000000000000000f", "3 * 5 = 15");

    // verify with python:
    // a = 0xDEADBEEF, b = 0xCAFEBABE
    // a * b = 0xA97C5B6A5765E942  (python: hex(0xDEADBEEF * 0xCAFEBABE))
    a = (BigNum){ .limbs = {0xDEADBEEF}, .size = 1 };
    b = (BigNum){ .limbs = {0xCAFEBABE}, .size = 1 };
    bignum_mul(&r, &a, &b);
    check_hex(&r, "00000000a97c5b6a5765e942", "0xDEADBEEF * 0xCAFEBABE");
    // python: hex(0xDEADBEEF * 0xCAFEBABE) → 0xa97c5b6a5765e942

    // multiply by zero
    a = (BigNum){ .limbs = {0xFFFFFFFFFFFFFFFF}, .size = 1 };
    b = (BigNum){ .limbs = {0}, .size = 1 };
    bignum_mul(&r, &a, &b);
    check_hex(&r, "0000000000000000", "x * 0 = 0");

    // two 2-limb numbers
    // a = 0x0000000100000000_0000000000000001
    // b = 0x0000000000000002
    // python: hex(a * b)
    a = (BigNum){ .limbs = {0x0000000000000001, 0x0000000100000000}, .size = 2 };
    b = (BigNum){ .limbs = {0x2}, .size = 1 };
    bignum_mul(&r, &a, &b);
    check_hex(&r, "00000000200000000000000000000002", "2-limb * scalar");
}

// ── cmp tests ─────────────────────────────────────────────────
void test_cmp() {
    printf("\n[cmp]\n");
    BigNum a, b;

    a = (BigNum){ .limbs = {5}, .size = 1 };
    b = (BigNum){ .limbs = {3}, .size = 1 };
    int r = bignum_cmp(&a, &b);
    if (r == 1)  PASS("5 > 3 → 1");
    else         FAIL("5 > 3 → 1", "got %d", r);

    r = bignum_cmp(&b, &a);
    if (r == -1) PASS("3 < 5 → -1");
    else         FAIL("3 < 5 → -1", "got %d", r);

    r = bignum_cmp(&a, &a);
    if (r == 0)  PASS("5 == 5 → 0");
    else         FAIL("5 == 5 → 0", "got %d", r);

    // different sizes
    a = (BigNum){ .limbs = {0xFFFFFFFFFFFFFFFF, 1}, .size = 2 };
    b = (BigNum){ .limbs = {0xFFFFFFFFFFFFFFFF},    .size = 1 };
    r = bignum_cmp(&a, &b);
    if (r == 1)  PASS("2-limb > 1-limb");
    else         FAIL("2-limb > 1-limb", "got %d", r);
}

// ── mod tests ─────────────────────────────────────────────────
void test_mod() {
    printf("\n[mod]\n");
    BigNum a, m, r;

    // 10 mod 3 = 1
    a = (BigNum){ .limbs = {10}, .size = 1 };
    m = (BigNum){ .limbs = {3},  .size = 1 };
    bignum_mod(&r, &a, &m);
    check_hex(&r, "0000000000000001", "10 mod 3 = 1");

    // 100 mod 7 = 2
    a = (BigNum){ .limbs = {100}, .size = 1 };
    m = (BigNum){ .limbs = {7},   .size = 1 };
    bignum_mod(&r, &a, &m);
    check_hex(&r, "0000000000000002", "100 mod 7 = 2");

    // a < m → result = a
    a = (BigNum){ .limbs = {3},  .size = 1 };
    m = (BigNum){ .limbs = {10}, .size = 1 };
    bignum_mod(&r, &a, &m);
    check_hex(&r, "0000000000000003", "3 mod 10 = 3");

    // your RSA exercise: 256 mod 101 = 54
    a = (BigNum){ .limbs = {256}, .size = 1 };
    m = (BigNum){ .limbs = {101}, .size = 1 };
    bignum_mod(&r, &a, &m);
    check_hex(&r, "0000000000000036", "256 mod 101 = 54");
}

// ── the real milestone: 2^79 mod 101 = 42 ────────────────────
// this requires modexp which you haven't written yet
// leaving the skeleton so you can uncomment it after layer 2
/*
void test_modexp() {
    printf("\n[modexp]\n");
    BigNum base = { .limbs = {2},   .size = 1 };
    BigNum exp  = { .limbs = {79},  .size = 1 };
    BigNum mod  = { .limbs = {101}, .size = 1 };
    BigNum r;
    modexp(&r, &base, &exp, &mod);
    check_hex(&r, "000000000000002a", "2^79 mod 101 = 42");
}
*/

// ── main ──────────────────────────────────────────────────────
int main(void) {
    printf("=== bignum tests ===");
    test_add();
    test_sub();
    test_mul();
    test_cmp();
    test_mod();

    printf("\n%d/%d passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}