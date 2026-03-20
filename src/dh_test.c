//
// Created by biprarshi on 20/03/2026.
//

#include "bignum.h"
#include "dh.h"

#include <stdio.h>

static int tests_run    = 0;
static int tests_passed = 0;

#define PASS(name) do { tests_run++; tests_passed++; \
printf("  PASS  %s\n", name); } while(0)
#define FAIL(name, ...) do { tests_run++; \
printf("  FAIL  %s — ", name); printf(__VA_ARGS__); printf("\n"); } while(0)

void test_dh() {
    printf("\n[dh]\n");

    DH_CTX alice, bob;

    // each generates independent private key
    // computes their own public key
    dh_init(&alice);
    dh_init(&bob);

    printf("  alice public key: ");
    bignum_print(&alice.pub);
    printf("  bob   public key: ");
    bignum_print(&bob.pub);

    // alice computes shared using bob's public key
    BigNum alice_shared;
    dh_compute_shared(&alice, &bob.pub, &alice_shared);

    // bob computes shared using alice's public key
    BigNum bob_shared;
    dh_compute_shared(&bob, &alice.pub, &bob_shared);

    // they must match — this is the DH guarantee
    if (bignum_cmp(&alice_shared, &bob_shared) == 0)
        PASS("alice and bob derive same shared secret");
    else
        FAIL("shared secret mismatch", "DH broken");
}

int main() {
    test_dh();
}