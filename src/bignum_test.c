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
    check_hex(&r, "b092ab7b88cf5b62", "0xDEADBEEF * 0xCAFEBABE");
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

void test_barrett() {
    printf("\n[barrett]\n");

    BigNum m = { .limbs = {101}, .size = 1 };
    BarrettCtx ctx;
    barrett_precompute(&ctx, &m);

    // 256 mod 101 = 54
    BigNum a = { .limbs = {256}, .size = 1 };
    BigNum r;
    bignum_barrett_mod(&r, &a, &ctx);
    check_hex(&r, "0000000000000036", "256 mod 101 = 54");

    // 9604 mod 101 = 9  (from your RSA exercise, step 5)
    a = (BigNum){ .limbs = {9604}, .size = 1 };
    bignum_barrett_mod(&r, &a, &ctx);
    check_hex(&r, "0000000000000009", "9604 mod 101 = 9");

    // the milestone: 2^79 mod 101 = 42
    BigNum base = { .limbs = {2},  .size = 1 };
    BigNum exp  = { .limbs = {79}, .size = 1 };
    mod_exp_barrett(&r, &base, &exp, &ctx);
    check_hex(&r, "000000000000002a", "2^79 mod 101 = 42");
}

// ── the real milestone: 2^79 mod 101 = 42 ────────────────────
// this requires modexp which you haven't written yet
// leaving the skeleton so you can uncomment it after layer 2
void test_modexp() {
    printf("\n[modexp]\n");
    BigNum base = { .limbs = {2},   .size = 1 };
    BigNum exp  = { .limbs = {79},  .size = 1 };
    BigNum mod  = { .limbs = {101}, .size = 1 };
    BigNum r;
    modexp(&r, &base, &exp, &mod);
    check_hex(&r, "000000000000002a", "2^79 mod 101 = 42");
}


void test_hex_conversion() {
    printf("\n[hex conversion tests]\n");
    BigNum n;
    char out_buf[1024];

    // --- Test 1: Single limb small value ---
    const char *hex1 = "000000000000000a"; // 10 decimal
    bignum_from_hex(&n, hex1);
    bignum_to_hex(&n, out_buf);

    if (n.limbs[0] == 10 && n.size == 1) {
        printf("  PASS: Single limb conversion (Value: %llu)\n", n.limbs[0]);
    } else {
        printf("  FAIL: Single limb conversion. Got size %d, limb[0] %llu\n", n.size, n.limbs[0]);
    }

    // --- Test 2: Multi-limb round trip ---
    // This tests if limbs are stored in the correct order (Little Endian limbs)
    const char *hex2 = "00000000000000010000000000000002";
    bignum_from_hex(&n, hex2);
    bignum_to_hex(&n, out_buf);

    if (strcmp(out_buf, hex2) == 0) {
        printf("  PASS: Multi-limb round trip\n");
    } else {
        printf("  FAIL: Multi-limb round trip.\n  Want: %s\n  Got : %s\n", hex2, out_buf);
    }

    // --- Test 3: Large value (3 limbs) ---
    const char *hex3 = "deadbeefdeadbeefcafebabecafebabebad1ad1bad1ad1ba";
    bignum_from_hex(&n, hex3);
    bignum_to_hex(&n, out_buf);

    // Note: your to_hex uses %016llx, so it might add leading zeros if the
    // original string wasn't a perfect multiple of 16. Adjusting comparison:
    if (strstr(out_buf, "deadbeefdeadbeefcafebabecafebabebad1ad1bad1ad1ba")) {
        printf("  PASS: Large 3-limb conversion\n");
    } else {
        printf("  FAIL: Large 3-limb conversion. Got: %s\n", out_buf);
    }
}

void test_print() {
    printf("\n[print test - visual check]\n");
    BigNum n;
    // 0xDE...BE in limb 1, 0xCA...BE in limb 0
    n.size = 2;
    n.limbs[1] = 0xDEADBEEFDEADBEEF;
    n.limbs[0] = 0xCAFEBABECAFEBABE;

    printf("Expected: 0xdeadbeefdeadbeefcafebabecafebab\n");
    printf("Actual:   ");
    bignum_print(&n);
    printf("\n");
}

// ── main ──────────────────────────────────────────────────────
int main(void) {
    printf("=== bignum tests ===");
    test_add();
    test_sub();
    test_mul();
    test_cmp();
    test_mod();
    test_barrett();
    test_modexp();
    test_hex_conversion();
    test_print();

    static const char *prime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

    BigNum p;
    bignum_from_hex(&p, prime);
    char buf[1024];
    bignum_to_hex(&p, buf);
    printf("%s\n", buf);


    printf("\n%d/%d passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}