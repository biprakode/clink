//
// Created by biprarshi on 21/03/2026.
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../aes.h"

static int tests_run    = 0;
static int tests_passed = 0;

#define PASS(name) do { tests_run++; tests_passed++; \
printf("  PASS  %s\n", name); } while(0)
#define FAIL(name, ...) do { tests_run++; \
printf("  FAIL  %s — ", name); printf(__VA_ARGS__); printf("\n"); } while(0)

// helper: parse hex string into byte array
static void hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

// helper: format byte array as hex string
static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + 2 * i, "%02x", in[i]);
    }
    out[2 * len] = '\0';
}

// NIST FIPS 197 Appendix C.3 — AES-256 test vector
void test_aes256_nist_vector(void) {
    const char *key_hex   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const char *plain_hex = "00112233445566778899aabbccddeeff";
    const char *expect_hex = "8ea2b7ca516745bfeafc49904b496089";

    uint8_t key[32], plaintext[16], ciphertext[16];
    hex_to_bytes(key_hex, key, 32);
    hex_to_bytes(plain_hex, plaintext, 16);

    aes256_block_encrypt(key, plaintext, ciphertext);

    char got[33];
    bytes_to_hex(ciphertext, 16, got);

    if (strcmp(got, expect_hex) == 0) {
        PASS("AES-256 NIST vector");
    } else {
        FAIL("AES-256 NIST vector", "expected %s, got %s", expect_hex, got);
    }
}

// all-zero key and all-zero plaintext
void test_aes256_zero_key(void) {
    const char *key_hex    = "0000000000000000000000000000000000000000000000000000000000000000";
    const char *plain_hex  = "00000000000000000000000000000000";
    const char *expect_hex = "dc95c078a2408989ad48a21492842087";

    uint8_t key[32], plaintext[16], ciphertext[16];
    hex_to_bytes(key_hex, key, 32);
    hex_to_bytes(plain_hex, plaintext, 16);

    aes256_block_encrypt(key, plaintext, ciphertext);

    char got[33];
    bytes_to_hex(ciphertext, 16, got);

    if (strcmp(got, expect_hex) == 0) {
        PASS("AES-256 zero key/plaintext");
    } else {
        FAIL("AES-256 zero key/plaintext", "expected %s, got %s", expect_hex, got);
    }
}

// all-ff key, all-ff plaintext
void test_aes256_all_ff(void) {
    const char *key_hex    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const char *plain_hex  = "ffffffffffffffffffffffffffffffff";
    const char *expect_hex = "d5f93d6d3311cb309f23621b02fbd5e2";

    uint8_t key[32], plaintext[16], ciphertext[16];
    hex_to_bytes(key_hex, key, 32);
    hex_to_bytes(plain_hex, plaintext, 16);

    aes256_block_encrypt(key, plaintext, ciphertext);

    char got[33];
    bytes_to_hex(ciphertext, 16, got);

    if (strcmp(got, expect_hex) == 0) {
        PASS("AES-256 all-FF key/plaintext");
    } else {
        FAIL("AES-256 all-FF key/plaintext", "expected %s, got %s", expect_hex, got);
    }
}

// encrypt two different plaintexts with the same key — outputs must differ
void test_aes256_different_plaintexts(void) {
    uint8_t key[32];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32);

    uint8_t pt1[16], pt2[16], ct1[16], ct2[16];
    hex_to_bytes("00112233445566778899aabbccddeeff", pt1, 16);
    hex_to_bytes("ffeeddccbbaa99887766554433221100", pt2, 16);

    aes256_block_encrypt(key, pt1, ct1);
    aes256_block_encrypt(key, pt2, ct2);

    if (memcmp(ct1, ct2, 16) != 0) {
        PASS("AES-256 different plaintexts produce different ciphertexts");
    } else {
        FAIL("AES-256 different plaintexts produce different ciphertexts", "outputs are identical");
    }
}

// encrypt same plaintext with two different keys — outputs must differ
void test_aes256_different_keys(void) {
    uint8_t key1[32], key2[32], pt[16], ct1[16], ct2[16];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key1, 32);
    hex_to_bytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", key2, 32);
    hex_to_bytes("00112233445566778899aabbccddeeff", pt, 16);

    aes256_block_encrypt(key1, pt, ct1);
    aes256_block_encrypt(key2, pt, ct2);

    if (memcmp(ct1, ct2, 16) != 0) {
        PASS("AES-256 different keys produce different ciphertexts");
    } else {
        FAIL("AES-256 different keys produce different ciphertexts", "outputs are identical");
    }
}

int main(void) {
    printf("[aes]\n");
    test_aes256_nist_vector();
    test_aes256_zero_key();
    test_aes256_all_ff();
    test_aes256_different_plaintexts();
    test_aes256_different_keys();
    printf("\n%d / %d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
