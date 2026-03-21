//
// Created by biprarshi on 21/03/2026.
//


#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


uint8_t *sha256_pad(const uint8_t *data , size_t len, size_t *padded_len) {
    size_t buffer_size = len + 1 + 8 + 63; // data + 0x80 + length + max padding
    buffer_size = (buffer_size / 64) * 64;
    uint8_t *padded_message = (uint8_t *)malloc(sizeof(uint8_t)  * buffer_size);

    memcpy(padded_message, data, len);
    size_t len_bytes = len;
    padded_message[len] = 0x80; // append 1
    len_bytes++;

    size_t padding_len = 0;
    if ((len_bytes % SHA256_BLOCK_SIZE) > 56) {
        // If less than 9 bytes remain in the current block, pad to the next blocks 56-byte mark
        padding_len = SHA256_BLOCK_SIZE - (len_bytes % SHA256_BLOCK_SIZE) + 56;
    } else {
        padding_len = 56 - (len_bytes % SHA256_BLOCK_SIZE);
    }

    memset(padded_message + len_bytes , 0 , padding_len);
    len_bytes += padding_len;

    // convert original message len to BigEndian of SHA256LENGTH (8)
    uint64_t original_len_bits = len * 8;
    padded_message[len_bytes] = (uint8_t)(original_len_bits >> 56);
    padded_message[len_bytes + 1] = (uint8_t)(original_len_bits >> 48);
    padded_message[len_bytes + 2] = (uint8_t)(original_len_bits >> 40);
    padded_message[len_bytes + 3] = (uint8_t)(original_len_bits >> 32);
    padded_message[len_bytes + 4] = (uint8_t)(original_len_bits >> 24);
    padded_message[len_bytes + 5] = (uint8_t)(original_len_bits >> 16);
    padded_message[len_bytes + 6] = (uint8_t)(original_len_bits >> 8);
    padded_message[len_bytes + 7] = (uint8_t)(original_len_bits >> 0);
    len_bytes += SHA256_LENGTH_SIZE;

    *padded_len = len_bytes;
    return padded_message;
}

void sha256_message_schedule(uint32_t w[64], const uint8_t *block) {
    // Initialize first 16 words from input block
    for (int t = 0; t < 16; t++) {
        w[t] = ((uint32_t)block[t * 4] << 24) |
               ((uint32_t)block[t * 4 + 1] << 16) |
               ((uint32_t)block[t * 4 + 2] << 8) |
               ((uint32_t)block[t * 4 + 3]);
    }

    // 2. Expand into 64 words
    for (int t = 16; t < 64; t++) {
        w[t] = SIG1(w[t - 2]) + w[t - 7] + SIG0(w[t - 15]) + w[t - 16];
    }
}

void sha256_compress(uint32_t H[8], const uint8_t *block) {
    // Step 1: build the 64-word message schedule from this 64-byte block
    uint32_t W[64];
    sha256_message_schedule(W, block);

    // Step 2: initialize working variables from current hash state
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];

    // Step 3: 64 rounds of compression
    for (int t = 0; t < 64; t++) {
        // T1 combines: current h, choice function on e/f/g, round constant, schedule word
        uint32_t T1 = h + SSIG1(e) + Ch(e, f, g) + K[t] + W[t];
        // T2 combines: majority function on a/b/c
        uint32_t T2 = SSIG0(a) + Maj(a, b, c);

        // shift all variables down by one position
        h = g;
        g = f;
        f = e;
        e = d + T1;    // e gets the T1 injection
        d = c;
        c = b;
        b = a;
        a = T1 + T2;   // a gets both T1 and T2
    }

    // Step 4: add compressed chunk back into hash state
    // this is what makes SHA-256 a Merkle-Damgard construction —
    // each block's output feeds into the next block's input
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

void sha256(const uint8_t *data, size_t len, uint8_t digest[32]) {
    // initialize hash state with fractional parts of square roots of first 8 primes
    uint32_t H[8];
    H[0] = 0x6a09e667;
    H[1] = 0xbb67ae85;
    H[2] = 0x3c6ef372;
    H[3] = 0xa54ff53a;
    H[4] = 0x510e527f;
    H[5] = 0x9b05688c;
    H[6] = 0x1f83d9ab;
    H[7] = 0x5be0cd19;

    // pad message to a multiple of 64 bytes
    size_t padded_len = 0;
    uint8_t *padded_data = sha256_pad(data , len , &padded_len);

    // compress each 64-byte block into the hash state
    for (size_t i = 0 ; i < padded_len / 64 ; i++) {
        sha256_compress(H, padded_data + i * 64);
    }

    // pack H[0..7] into digest[0..31] as big-endian bytes
    for (int i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(H[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(H[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(H[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(H[i]);
    }

    free(padded_data);
}
