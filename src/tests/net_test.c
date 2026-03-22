//
// Created by biprarshi on 22/03/2026.
//
// Tests net_listen, net_connect, net_send, net_recv using fork()
// The parent acts as server, the child as client — both on localhost.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../net.h"

static int tests_run    = 0;
static int tests_passed = 0;

#define PASS(name) do { tests_run++; tests_passed++; \
printf("  PASS  %s\n", name); } while(0)
#define FAIL(name, ...) do { tests_run++; \
printf("  FAIL  %s — ", name); printf(__VA_ARGS__); printf("\n"); } while(0)

#define TEST_PORT 9877

int main(void) {
    printf("[net]\n");

    pid_t pid = fork();

    if (pid == 0) {
        // ---------- child = client ----------
        usleep(100000);  // 100ms — give server time to start listening

        int fd = net_connect("127.0.0.1", TEST_PORT);
        if (fd < 0) { fprintf(stderr, "client: connect failed\n"); exit(1); }

        // test 1: send a short message
        const char *msg = "hello from client";
        net_send(fd, (const uint8_t *)msg, strlen(msg));

        // test 2: receive server's response
        uint8_t *data = NULL;
        uint32_t len = 0;
        net_recv(fd, &data, &len);
        // send back what we got so server can verify round-trip
        net_send(fd, data, len);
        free(data);

        // test 3: send a large message (4096 bytes) to test looping in write_all/read_all
        uint8_t big[4096];
        for (int i = 0; i < 4096; i++) big[i] = (uint8_t)(i & 0xFF);
        net_send(fd, big, 4096);

        net_close(fd);
        exit(0);

    } else {
        // ---------- parent = server ----------
        int fd = net_listen(TEST_PORT);
        if (fd < 0) { fprintf(stderr, "server: listen failed\n"); return 1; }

        // test 1: receive client's short message
        uint8_t *data = NULL;
        uint32_t len = 0;
        if (net_recv(fd, &data, &len) == 0 &&
            len == strlen("hello from client") &&
            memcmp(data, "hello from client", len) == 0) {
            PASS("send/recv short message");
        } else {
            FAIL("send/recv short message", "got unexpected data");
        }
        free(data);

        // test 2: send response, client echoes it back — verify round-trip
        const char *reply = "hello from server";
        net_send(fd, (const uint8_t *)reply, strlen(reply));

        data = NULL;
        len = 0;
        if (net_recv(fd, &data, &len) == 0 &&
            len == strlen(reply) &&
            memcmp(data, reply, len) == 0) {
            PASS("round-trip echo");
        } else {
            FAIL("round-trip echo", "echoed data doesn't match");
        }
        free(data);

        // test 3: receive large message
        data = NULL;
        len = 0;
        int large_ok = 1;
        if (net_recv(fd, &data, &len) == 0 && len == 4096) {
            for (int i = 0; i < 4096; i++) {
                if (data[i] != (uint8_t)(i & 0xFF)) { large_ok = 0; break; }
            }
        } else {
            large_ok = 0;
        }
        if (large_ok) {
            PASS("send/recv large message (4096 bytes)");
        } else {
            FAIL("send/recv large message (4096 bytes)", "data mismatch or wrong length");
        }
        free(data);

        net_close(fd);

        // wait for child to finish
        waitpid(pid, NULL, 0);

        printf("\n%d / %d tests passed\n", tests_passed, tests_run);
        return tests_passed == tests_run ? 0 : 1;
    }
}
