# clink — Encrypted Remote Shell over TCP
## Project Guide for Claude Code

---

## How to work with this developer

**This developer is learning cryptography and systems programming. Follow these rules strictly:**

- **Default mode: hints only.** Point to the problem, ask a guiding question, let them write the code.
- **If they explicitly ask for code:** write it fully with clear explanation.
- **If they say they don't understand:** teach the concept first, then show code.
- **Never fix multiple things at once.** One problem, one hint, wait for response.
- **Never be dismissive.** They have built a working bignum library, Barrett reduction, and DH from scratch. That is not beginner work.
- **Python is the oracle.** For any crypto output question, suggest verifying against Python before assuming the C is wrong.
- **Tests first.** Before debugging, ask what the test output is.

---

## What clink is

A command-line tool that establishes a Diffie-Hellman key exchange over TCP, derives a shared AES key, and lets one machine execute commands on another over an encrypted tunnel. No external crypto libraries. Everything implemented from scratch in C.

```
[client]  ── TCP connect ──────────────►  [server]
             DH handshake
             derive AES-256 key
[client]  ── encrypt("ls -la") ─────────►  [server]
                                            popen("ls -la")
[client]  ◄─ encrypt(output) ────────────  [server]
```

---

## Current status

### DONE
- [x] BigNum struct — 64-limb uint64_t array
- [x] bignum_add, bignum_sub, bignum_mul
- [x] bignum_mod (binary long division)
- [x] bignum_cmp, bignum_trim, bignum_copy
- [x] bignum_lshift, bignum_rshift (1-bit)
- [x] bignum_shl, bignum_shr (n-bit)
- [x] bignum_bit_set, bignum_bit_len
- [x] bignum_from_hex, bignum_to_hex
- [x] bignum_from_bytes
- [x] modexp (square-and-multiply)
- [x] Barrett precompute + barrett_mod
- [x] mod_exp_barrett
- [x] DHContext struct
- [x] dh_init (load RFC 3526 prime, generate private key, compute public key)
- [x] dh_compute_shared

### IN PROGRESS — BROKEN
- [ ] DH test: alice and bob derive same shared secret

### NOT STARTED
- [ ] AES-256 block cipher
- [ ] AES-CTR mode
- [ ] SHA-256 (for KDF)
- [ ] Key derivation: shared_secret → AES key + IV
- [ ] TCP framing (length-prefixed send/recv)
- [ ] Tunnel handshake (DH over socket)
- [ ] Encrypted tunnel send/recv
- [ ] Server: accept connection, exec commands, send output
- [ ] Client: connect, send commands, display output

---

## CURRENT DEBUGGING TASK — Fix DH overflow

### The error

```
barrett_mod: correction overflow
barrett_mod: correction overflow
FATAL bignum_mul overflow: 110 + 110 > 128
```

### What is happening — explain to developer

The DH prime p is 2048 bits = 32 limbs. During Barrett modexp:

1. `mod_exp_barrett` computes `res * res` or `res * base`
2. These are ~32-limb numbers
3. `bignum_mul` of two 32-limb numbers needs up to 64 limbs for the result
4. Barrett then computes `q1 * mu` where both can be ~64 limbs
5. That product needs up to 128 limbs

The current `MAX_LIMBS = 64` is not enough for Barrett intermediates.

### The deeper problem — explain to developer

Barrett reduction on a k-bit modulus requires intermediate values up to 4k bits:

```
m        = 2048 bits = 32 limbs
mu       = 2048 bits = 32 limbs   (floor(2^4096 / m))
a        = up to 4096 bits = 64 limbs  (product of two mod-p values)
q1       = a >> (k-1)              = up to 64 limbs
q2       = q1 * mu                 = up to 128 limbs   ← THIS IS THE PROBLEM
q3       = q2 >> (k+1)             = up to 64 limbs
q3m      = q3 * m                  = up to 96 limbs
```

So `bignum_mul` needs to handle at least 128 limbs. And `MAX_LIMBS` must be 128.

### Hint sequence for developer

**Hint 1:** Where is `MAX_LIMBS` defined? What is it currently set to? What does the fatal error tell you it needs to be?

**Hint 2:** `MAX_LIMBS` controls the array size in the `BigNum` struct. If you change it, every `BigNum` on the stack gets larger. Is that a problem? (Answer: no, they're stack-allocated, just a bit more memory per struct.)

**Hint 3:** After fixing `MAX_LIMBS`, the correction overflow in `barrett_mod` suggests `mu` was computed incorrectly. Add a debug print of `ctx->mu` after `barrett_precompute` and verify it against Python:
```python
p = 0xFFFFFFFF...  # RFC 3526 prime
k = 2048
mu = (2 ** (2*k)) // p
print(hex(mu))
```

**Hint 4:** If `mu` looks wrong, trace `barrett_precompute`. Check that `bignum_shl(&power, &power, 2 * ctx->k)` is actually producing `2^4096`. Print `power` before the division.

**Hint 5:** `bignum_shl` does an in-place shift on a copy — but the source and destination are the same pointer (`&power, &power`). Does your `bignum_shl` handle aliasing (src == dst)? Check the implementation.

### Expected result after fix

```
[dh]
  alice public key: 0x[2048-bit number]
  bob   public key: 0x[different 2048-bit number]
  PASS  alice and bob derive same shared secret
```

Both shared secrets must be identical 2048-bit numbers. Verify one of them against Python:
```python
g = 2
p = int("ffffffff...ffffffff", 16)  # RFC 3526
a = int("your_alice_private_key_hex", 16)
b = int("your_bob_private_key_hex", 16)
A = pow(g, a, p)
B = pow(g, b, p)
assert pow(B, a, p) == pow(A, b, p)
print(hex(pow(B, a, p)))  # compare with C output
```

---

## Project structure

```
clink/
├── src/
│   ├── bignum.h / bignum.c        ← DONE (needs MAX_LIMBS fix)
│   ├── dh.h / dh.c                ← DONE (blocked on bignum bug)
│   ├── aes.h / aes.c              ← NOT STARTED
│   ├── kdf.h / kdf.c              ← NOT STARTED
│   ├── tunnel.h / tunnel.c        ← NOT STARTED
│   ├── net.h / net.c              ← NOT STARTED
│   ├── main_server.c              ← NOT STARTED
│   └── main_client.c              ← NOT STARTED
├── tests/
│   ├── test_bignum.c              ← DONE
│   ├── test_dh.c                  ← IN PROGRESS
│   ├── test_aes.c                 ← NOT STARTED
│   └── test_tunnel.c              ← NOT STARTED
└── Makefile
```

---

## Layer 4 — AES-256 + KDF (next after DH fixed)

### What to build

```c
// core AES block — encrypts exactly 16 bytes
void aes256_block_encrypt(const uint8_t key[32],
                          const uint8_t in[16],
                          uint8_t out[16]);

// CTR mode — encrypts arbitrary length, same function for decrypt
void aes256_ctr(const uint8_t key[32],
                const uint8_t iv[16],
                const uint8_t *in,
                uint8_t *out,
                size_t len);

// KDF — derive key and IV from DH shared secret
void kdf(const BigNum *shared_secret,
         uint8_t key_out[32],
         uint8_t iv_out[16]);
```

### AES internals hint

AES-256 has 14 rounds. Each round: SubBytes → ShiftRows → MixColumns → AddRoundKey.
Last round skips MixColumns. Key schedule expands 32-byte key into 15 round keys.
FIPS 197 is the spec — it has intermediate test vectors for every operation.

### CTR mode hint

```
keystream_block = AES(key, counter)
ciphertext      = plaintext XOR keystream_block
counter++
```
Decrypt is identical to encrypt — XOR is its own inverse.

### KDF hint

The DH shared secret is a 2048-bit number. AES wants 32 bytes.
SHA-256 of the shared secret bytes gives you 32 bytes.
Use the first 32 bytes as the key, SHA-256 of (secret || 0x01) for the IV.

### How to test AES

NIST publishes official AES-256 test vectors. If your output matches for the known inputs, your AES is correct. No guessing.

```
key:   000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
input: 00112233445566778899aabbccddeeff
output: 8ea2b7ca516745bfeafc49904b496089
```

---

## Layer 5 — Network + Tunnel

### TCP framing

TCP is a stream. `recv()` can return partial data. Every message must be prefixed with its length:

```
[4 bytes: length (big-endian)] [length bytes: payload]
```

```c
int net_send(int fd, const uint8_t *data, uint32_t len);
int net_recv(int fd, uint8_t **data, uint32_t *len);
```

`net_recv` must loop until it has read exactly `len` bytes.

### Tunnel handshake sequence

```
Client                          Server
  |── TCP connect ──────────────►|
  |── send DH public key ────────►|   (bignum_to_hex, then send as bytes)
  |◄─ send DH public key ─────────|
  |                               |
  both: dh_compute_shared()
  both: kdf(shared) → key, iv
  |                               |
  tunnel live — all further messages encrypted
```

### Encrypted send/recv

```c
typedef struct {
    int     fd;
    uint8_t key[32];
    uint8_t iv[16];
    uint64_t counter;   // increment per message — ensures unique nonce
} Tunnel;

int tunnel_send(Tunnel *t, const uint8_t *plaintext, uint32_t len);
int tunnel_recv(Tunnel *t, uint8_t **plaintext, uint32_t *len);
```

Each message: encrypt with AES-CTR using (key, iv XOR counter), then net_send. Increment counter.

---

## Layer 6 — Application

### Server (main_server.c)

```
listen on port argv[1]
accept one connection
tunnel_handshake_server()
loop:
    tunnel_recv() → command string
    popen(command) → read output
    tunnel_send(output)
```

### Client (main_client.c)

```
connect to argv[1]:argv[2]
tunnel_handshake_client()
loop:
    print "clink> "
    fgets(stdin) → command string
    tunnel_send(command)
    tunnel_recv() → output
    fwrite(output, stdout)
```

---

## Milestones (in order)

```
[x] M1 — bignum_mul(a,b) matches Python a*b
[x] M2 — modexp(2, 79, 101) == 42
[x] M3 — Barrett: barrett_mod(256, 101) == 54
[~] M4 — DH: alice and bob derive same shared secret   ← CURRENT
[ ] M5 — AES NIST test vectors pass
[ ] M6 — KDF produces consistent key+IV from shared secret
[ ] M7 — two processes exchange encrypted messages on localhost
[ ] M8 — client sends "ls", server responds with output
[ ] M9 — works on LAN (two machines)
[ ] M10 — works on WAN (VPS)
```

---

## Key rules

**Python is the oracle for all crypto.**
```python
# verify any bignum operation
pow(base, exp, mod)           # modexp
(2 ** (2*2048)) // p          # Barrett mu
pow(g, a, p)                  # DH public key
pow(their_pub, my_priv, p)    # DH shared secret
```

**Fail loudly, not silently.**
Every overflow, every bad state — `abort()`, not `return`. Silent failures corrupt downstream state invisibly.

**Test each layer before building the next.**
A bug in bignum corrupts DH. A bug in DH corrupts the tunnel. A bug in the tunnel corrupts every command. The layering only works if each layer is verified independently.

**Never use `rand()` for crypto.**
`/dev/urandom` only.

**Never expose the private key.**
`DHContext.x` never leaves the struct, never gets printed, never goes on the wire.