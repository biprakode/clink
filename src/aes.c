//
// Created by biprarshi on 21/03/2026.
//

#include "bignum.h"
#include "aes.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void RotWord(uint8_t *word) {
    //[a , b , c , d] = [b , c , d , a]
    uint8_t tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

void SubWord(uint8_t *bytes) {
    //sbox substitute
    for (int i = 0 ; i < 4 ; i++) {
        bytes[i] = sbox[bytes[i]];
    }
}

void RC(uint8_t *rc , int round) {
    switch (round) {
        case 1:
            *rc = 0x01;
            break;
        case 2:
            *rc = 0x02;
            break;
        case 3:
            *rc = 0x04;
            break;
        case 4:
            *rc = 0x08;
            break;
        case 5:
            *rc = 0x10;
            break;
        case 6:
            *rc = 0x20;
            break;
        case 7:
            *rc = 0x40;
            break;
        default:
            *rc = 0x00;
    }
}

void aes256_key_expand(uint8_t key[32] , uint8_t round_keys[240]) {
    // copy original 32-byte key into words 0-7 (first 2 round keys)
    for (int i = 0 ; i<32 ; i++) {
        round_keys[i] = key[i];
    }

    // generate words 8-59 (round keys 2-14)
    for (int i = 8 ; i<60 ; i++) {
        // start with a copy of the previous word (word i-1)
        uint8_t temp[4];
        memcpy(temp , &round_keys[(i - 1) * 4] , 4);

        if (i % 8 == 0) {
            // every 8th word: RotWord + SubWord + XOR with round constant
            RotWord(temp);
            SubWord(temp);
            uint8_t r_coeff;
            RC(&r_coeff , i / 8);  // round number = word index / 8
            temp[0] ^= r_coeff;   // Rcon only affects the first byte
        }
        else if (i % 8 == 4) {
            // halfway through each 8-word group: SubWord only (AES-256 specific)
            SubWord(temp);
        }

        // XOR with the word 8 positions back to produce the new word
        for (int k = 0 ; k < 4 ; k++) {
            temp[k] ^= round_keys[(i - 8) * 4 + k];
        }
        // store the new word at its position
        memcpy(round_keys + i * 4 , temp , 4);
    }
}

void add_round_key(uint8_t round_key[240] , uint8_t state[16] , int round) {
    for (int i = 0 ; i<16 ; i++) {
        state[i] ^= round_key[round * 16 + i];
    }
}

void sub_bytes(uint8_t state[16] ) {
    for (int i = 0 ; i<16 ; i++) {
        state[i] = sbox[state[i]];
    }
}

void shift_rows(uint8_t state[16] ) {
    uint8_t temp[16];
    memcpy(temp , state , 16);
    state[0] = temp[0];
    state[1] = temp[5];
    state[2] = temp[10];
    state[3] = temp[15];
    state[4] = temp[4];
    state[5] = temp[9];
    state[6] = temp[14];
    state[7] = temp[3];
    state[8] = temp[8];
    state[9] = temp[13];
    state[10] = temp[2];
    state[11] = temp[7];
    state[12] = temp[12];
    state[13] = temp[1];
    state[14] = temp[6];
    state[15] = temp[11];
}

uint8_t xtime(uint8_t a) {
    //shift left by 1 bit
    //if the original high bit was 1: XOR with 0x1b (reducing poly)
    return (a << 1) ^ ((a & 0x80) ? 0x1b : 0x00);
}

uint8_t mul_3(uint8_t a) {
    return xtime(a) ^ a;
}

void mix_cols(uint8_t state[16] ) {
    for (int i = 0 ; i<4 ; i++) {
        uint8_t a = state[i * 4 + 0];
        uint8_t b = state[i * 4 + 1];
        uint8_t c = state[i * 4 + 2];
        uint8_t d = state[i * 4 + 3];

        state[i*4 + 0] = xtime(a) ^ mul_3(b) ^ c        ^ d;
        state[i*4 + 1] = a        ^ xtime(b) ^ mul_3(c)  ^ d;
        state[i*4 + 2] = a        ^ b        ^ xtime(c)  ^ mul_3(d);
        state[i*4 + 3] = mul_3(a) ^ b        ^ c         ^ xtime(d);
    }
}

void aes256_block_encrypt(const uint8_t key[32] , const uint8_t plaintext[16], uint8_t ciphertext[16]) {
    uint8_t state[16];
    uint8_t round_keys[240];
    aes256_key_expand(key, round_keys);
    memcpy(state , plaintext , 16);
    add_round_key(round_keys , state , 0 ) ;
    for (int i = 1 ; i<=13 ; i++) {
        sub_bytes(state);
        shift_rows(state);
        mix_cols(state);
        add_round_key(round_keys , state , i ) ;
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(round_keys , state , 14 ) ;
    memcpy(ciphertext , state , 16);
}

void aes256_ctr(const uint8_t key[32] , const uint8_t iv[16] , const uint8_t *in , uint8_t *out , size_t len) {
    uint8_t counter[16];
    memcpy(counter , iv , 16);

    size_t offset = 0;
    while (offset < len) {
        // encrypt the counter to produce a 16-byte keystream block
        uint8_t keystream[16];
        aes256_block_encrypt(key , counter , keystream);
        size_t block_len = (len - offset < 16) ? (len - offset) : (16 - offset); // handle last block maybe < 16 bytes

        // XOR keystream with plaintext
        for (size_t i = 0; i<block_len; i++) {
            out[offset + i] = in[offset + i] ^ counter[i];
        }

        offset += block_len;

        // increment counter as big-endian 128-bit integer
        for (int i = 15 ; i>=0; i--) {
            counter[i]++;
            if (counter[i] != 0) break;
        }
    }
}