//
// Created by biprarshi on 22/03/2026.
//
// Tests the full tunnel stack: DH handshake + encrypted send/recv over TCP.
// Uses fork() — parent = server, child = client, both on localhost.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../net.h"
#include "../tunnel.h"

static int tests_run    = 0;
static int tests_passed = 0;

#define PASS(name) do { tests_run++; tests_passed++; \
printf("  PASS  %s\n", name); } while(0)
#define FAIL(name, ...) do { tests_run++; \
printf("  FAIL  %s — ", name); printf(__VA_ARGS__); printf("\n"); } while(0)

#define TEST_PORT 9878

int main(void) {
    printf("[tunnel]\n");

    pid_t pid = fork();

    if (pid == 0) {
        // ---------- child = client ----------
        usleep(200000);  // 200ms — give server time to start listening

        int fd = net_connect("127.0.0.1", TEST_PORT);
        if (fd < 0) { fprintf(stderr, "client: connect failed\n"); exit(1); }

        // perform DH handshake (client sends first, then receives)
        Tunnel t;
        if (tunnel_handshake_client(&t, fd) < 0) {
            fprintf(stderr, "client: handshake failed\n");
            net_close(fd);
            exit(1);
        }

        // test 1: send a short message
        const char *msg = "hello encrypted world";
        tunnel_send(&t, (const uint8_t *)msg, strlen(msg));

        // test 2: receive server's reply
        uint8_t *reply = NULL;
        uint32_t reply_len = 0;
        tunnel_recv(&t, &reply, &reply_len);
        // echo it back so server can verify round-trip
        tunnel_send(&t, reply, reply_len);
        free(reply);

        // test 3: send a large message (4096 bytes)
        uint8_t big[4096];
        for (int i = 0; i < 4096; i++) big[i] = (uint8_t)(i & 0xFF);
        tunnel_send(&t, big, 4096);

        // test 4: send multiple messages to test counter increment
        const char *m1 = "message one";
        const char *m2 = "message two";
        const char *m3 = "message three";
        tunnel_send(&t, (const uint8_t *)m1, strlen(m1));
        tunnel_send(&t, (const uint8_t *)m2, strlen(m2));
        tunnel_send(&t, (const uint8_t *)m3, strlen(m3));

        net_close(fd);
        exit(0);

    } else {
        // ---------- parent = server ----------
        int fd = net_listen(TEST_PORT);
        if (fd < 0) { fprintf(stderr, "server: listen failed\n"); return 1; }

        // perform DH handshake (server receives first, then sends)
        Tunnel t;
        if (tunnel_handshake_server(&t, fd) < 0) {
            fprintf(stderr, "server: handshake failed\n");
            net_close(fd);
            waitpid(pid, NULL, 0);
            return 1;
        }
        PASS("handshake completes");

        // test 1: receive client's short encrypted message
        uint8_t *data = NULL;
        uint32_t len = 0;
        if (tunnel_recv(&t, &data, &len) == 0 &&
            len == strlen("hello encrypted world") &&
            memcmp(data, "hello encrypted world", len) == 0) {
            PASS("encrypted short message");
        } else {
            FAIL("encrypted short message", "decrypted data doesn't match");
        }
        free(data);

        // test 2: send reply, client echoes it back — verify encrypted round-trip
        const char *reply = "server says hello";
        tunnel_send(&t, (const uint8_t *)reply, strlen(reply));

        data = NULL;
        len = 0;
        if (tunnel_recv(&t, &data, &len) == 0 &&
            len == strlen(reply) &&
            memcmp(data, reply, len) == 0) {
            PASS("encrypted round-trip echo");
        } else {
            FAIL("encrypted round-trip echo", "echoed data doesn't match");
        }
        free(data);

        // test 3: receive large encrypted message (4096 bytes)
        data = NULL;
        len = 0;
        int large_ok = 1;
        if (tunnel_recv(&t, &data, &len) == 0 && len == 4096) {
            for (int i = 0; i < 4096; i++) {
                if (data[i] != (uint8_t)(i & 0xFF)) { large_ok = 0; break; }
            }
        } else {
            large_ok = 0;
        }
        if (large_ok) {
            PASS("encrypted large message (4096 bytes)");
        } else {
            FAIL("encrypted large message (4096 bytes)", "data mismatch or wrong length");
        }
        free(data);

        // test 4: receive multiple messages — tests that counters stay in sync
        const char *expected[] = {"message one", "message two", "message three"};
        int multi_ok = 1;
        for (int i = 0; i < 3; i++) {
            data = NULL;
            len = 0;
            if (tunnel_recv(&t, &data, &len) == 0 &&
                len == strlen(expected[i]) &&
                memcmp(data, expected[i], len) == 0) {
                // good
            } else {
                multi_ok = 0;
            }
            free(data);
        }
        if (multi_ok) {
            PASS("multiple messages (counter sync)");
        } else {
            FAIL("multiple messages (counter sync)", "one or more messages decrypted wrong");
        }

        net_close(fd);
        waitpid(pid, NULL, 0);

        printf("\n%d / %d tests passed\n", tests_passed, tests_run);
        return tests_passed == tests_run ? 0 : 1;
    }
}
