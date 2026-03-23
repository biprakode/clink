# clink

Encrypted remote shell over TCP. Zero external dependencies — every layer of the crypto stack is implemented from scratch in C.

Type a command on one machine, it gets encrypted, sent over the network, executed on the other machine, and the output comes back encrypted. An eavesdropper on the wire sees only ciphertext.

## Features

- **Diffie-Hellman key exchange** — RFC 3526 2048-bit MODP group, no pre-shared keys needed
- **AES-256-CTR encryption** — all traffic encrypted after handshake
- **SHA-256 key derivation** — shared secret hashed into AES key + IV
- **Length-prefixed TCP framing** — handles partial reads/writes correctly
- **Arbitrary-precision arithmetic** — BigNum library with Barrett reduction for fast modular exponentiation
- **~1500 lines of C** — no OpenSSL, no libsodium, no dependencies beyond libc

## Architecture

```
                  CLIENT                                        SERVER
            +-----------------+                          +-----------------+
            |  main_client.c  |                          |  main_server.c  |
            |  fgets(stdin)   |                          |  popen(cmd)     |
            +--------+--------+                          +--------+--------+
                     |                                            |
              tunnel_send/recv                             tunnel_send/recv
                     |                                            |
            +--------+--------+                          +--------+--------+
            |    tunnel.c     |                          |    tunnel.c     |
            |  AES-CTR encrypt|                          |  AES-CTR decrypt|
            |  nonce = iv^ctr |                          |  nonce = iv^ctr |
            +--------+--------+                          +--------+--------+
                     |                                            |
               net_send/recv          TCP (encrypted)       net_send/recv
                     |           [4-byte len][ciphertext]         |
            +--------+--------+  ======================== +-------+--------+
            |     net.c       |--------- NETWORK ---------|     net.c      |
            +-----------------+                           +----------------+
```

### Handshake sequence

```
    Client                                Server
      |                                     |
      |------------ TCP connect ----------->|
      |                                     |
      |--- DH public key (g^a mod p) ------>|
      |                                     |
      |<-- DH public key (g^b mod p) -------|
      |                                     |
      |  shared = (g^b)^a mod p             |  shared = (g^a)^b mod p
      |  key, iv = SHA256(shared)           |  key, iv = SHA256(shared)
      |                                     |
      |==== encrypted tunnel established ===|
      |                                     |
      |--- AES-CTR("ls -la") -------------->|
      |                                     |  output = popen("ls -la")
      |<-- AES-CTR(output) ----------------|
      |                                     |
```

### Crypto stack

```
Layer 5   main_server.c / main_client.c    Application — command I/O
Layer 4   tunnel.c                         Encrypted send/recv, DH handshake
Layer 3   net.c                            TCP framing (length-prefixed)
Layer 2   aes.c + kdf.c + sha256.c         AES-256-CTR, SHA-256, key derivation
Layer 1   dh.c                             Diffie-Hellman key exchange
Layer 0   bignum.c                         Arbitrary-precision integer arithmetic
```

## Build

Requires only `cmake` (>= 3.10) and a C compiler.

```bash
git clone <repo-url>
cd clink
mkdir build && cmake -B build . && cmake --build build
```

Binaries: `build/clink_server`, `build/clink_client`

## Usage

### Localhost

```bash
# terminal 1
./build/clink_server 4444

# terminal 2
./build/clink_client 127.0.0.1 4444
clink> whoami
alice
clink> ls /tmp
...
clink> exit
```

### LAN (two machines on the same network)

```bash
# machine A — find your LAN IP
ip addr show | grep "inet 192"
# e.g. 192.168.1.105

# machine A — start server
./build/clink_server 4444

# machine B — connect
./build/clink_client 192.168.1.105 4444
```

If connection times out, open the firewall on the server:

```bash
# Fedora
sudo firewall-cmd --add-port=4444/tcp
# Ubuntu
sudo ufw allow 4444/tcp
```

### WAN (over the internet via VPS)

```bash
# on VPS
git clone <repo> && cd clink
mkdir build && cmake -B build . && cmake --build build
sudo ufw allow 4444/tcp
./build/clink_server 4444

# from home
./build/clink_client <VPS_PUBLIC_IP> 4444
```

## Tests

```bash
cmake --build build
./build/tunnel_test     # full integration: DH + AES + network
./build/bignum_test     # arbitrary-precision arithmetic
./build/dh_test         # Diffie-Hellman key agreement
./build/aes_test        # AES-256 NIST test vectors
./build/sha256_test     # SHA-256
./build/net_test        # TCP framing
```

## Project structure

```
src/
  bignum.c / bignum.h       Arbitrary-precision integers (add, sub, mul, mod, modexp, Barrett)
  dh.c / dh.h               Diffie-Hellman (RFC 3526 prime, key generation, shared secret)
  aes.c / aes.h             AES-256 block cipher + CTR mode
  sha256.c / sha256.h       SHA-256 hash
  kdf.c / kdf.h             Key derivation (shared secret -> AES key + IV)
  net.c / net.h             TCP socket helpers (listen, connect, length-prefixed send/recv)
  tunnel.c / tunnel.h       Encrypted tunnel (DH handshake, AES-CTR send/recv)
  main_server.c             Server binary (accept, exec commands, send output)
  main_client.c             Client binary (connect, send commands, display output)
  tests/                    Test suite for each layer
```

## Security notes

This is an educational project. It demonstrates the concepts but is not hardened for production:

- **No authentication** — any client that knows the IP:port can connect
- **No replay protection** — beyond per-message nonce counters
- **No constant-time operations** — BigNum and AES implementations are not side-channel resistant
- **Single connection** — server handles one client at a time

## License

See [LICENSE](LICENSE).
