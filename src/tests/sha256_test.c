//
// Created by biprarshi on 21/03/2026.
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../sha256.h"

// sha256 is declared in sha256.h but implemented in sha256.c
extern void sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

static int tests_run    = 0;
static int tests_passed = 0;

#define PASS(name) do { tests_run++; tests_passed++; \
printf("  PASS  %s\n", name); } while(0)
#define FAIL(name, ...) do { tests_run++; \
printf("  FAIL  %s — ", name); printf(__VA_ARGS__); printf("\n"); } while(0)

static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + 2 * i, "%02x", in[i]);
    }
    out[2 * len] = '\0';
}

static void test_sha256_vector(const char *name, const uint8_t *data, size_t len, const char *expected_hex) {
    uint8_t digest[32];
    sha256(data, len, digest);

    char got[65];
    bytes_to_hex(digest, 32, got);

    if (strcmp(got, expected_hex) == 0) {
        PASS(name);
    } else {
        FAIL(name, "expected %s\n         got      %s", expected_hex, got);
    }
}

// NIST test vector: empty string
void test_empty(void) {
    test_sha256_vector(
        "SHA-256 empty string",
        (const uint8_t *)"", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// NIST test vector: "abc"
void test_abc(void) {
    test_sha256_vector(
        "SHA-256 \"abc\"",
        (const uint8_t *)"abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// NIST test vector: 448-bit message (two blocks after padding)
void test_two_blocks(void) {
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    test_sha256_vector(
        "SHA-256 two-block message",
        (const uint8_t *)msg, strlen(msg),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

// exactly 55 bytes — fits in one block (55 + 1 + 8 = 64)
void test_55_bytes(void) {
    uint8_t data[55];
    memset(data, 'a', 55);
    test_sha256_vector(
        "SHA-256 55 bytes (boundary: fits in one block)",
        data, 55,
        "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
    );
}

// exactly 56 bytes — needs two blocks (56 + 1 > 56, no room for length)
void test_56_bytes(void) {
    uint8_t data[56];
    memset(data, 'a', 56);
    test_sha256_vector(
        "SHA-256 56 bytes (boundary: needs two blocks)",
        data, 56,
        "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
    );
}

// different inputs produce different outputs
void test_different_inputs(void) {
    uint8_t d1[32], d2[32];
    sha256((const uint8_t *)"hello", 5, d1);
    sha256((const uint8_t *)"hellp", 5, d2);

    if (memcmp(d1, d2, 32) != 0) {
        PASS("SHA-256 different inputs produce different digests");
    } else {
        FAIL("SHA-256 different inputs produce different digests", "outputs are identical");
    }
}

// same input always produces same output
void test_deterministic(void) {
    uint8_t d1[32], d2[32];
    sha256((const uint8_t *)"test", 4, d1);
    sha256((const uint8_t *)"test", 4, d2);

    if (memcmp(d1, d2, 32) == 0) {
        PASS("SHA-256 deterministic (same input = same output)");
    } else {
        FAIL("SHA-256 deterministic (same input = same output)", "outputs differ");
    }
}

int main(void) {
    printf("[sha256]\n");
    test_empty();
    test_abc();
    test_two_blocks();
    test_55_bytes();
    test_56_bytes();
    test_different_inputs();
    test_deterministic();
    printf("\n%d / %d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
