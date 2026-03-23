//
// Created by biprarshi on 23/03/2026.
//
// clink client — connects to server, does DH handshake,
// then sends commands and displays their output.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"
#include "tunnel.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: clink_client <ip> <port>\n");
        return 1;
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);

    // step 1: connect to the server
    int fd = net_connect(ip, port);
    if (fd < 0) return 1;

    // step 2: DH handshake — after this, tunnel has the shared AES key
    Tunnel t;
    if (tunnel_handshake_client(&t, fd) < 0) {
        fprintf(stderr, "[client] handshake failed\n");
        net_close(fd);
        return 1;
    }

    // step 3: command loop — read input, send command, display output
    char line[4096];
    while (1) {
        printf("clink> ");
        fflush(stdout);  // prompt must appear before fgets blocks

        // fgets reads one line including the '\n', returns NULL on ctrl-D (EOF)
        if (fgets(line, sizeof(line), stdin) == NULL) {
            printf("\n");  // newline after ctrl-D for clean terminal
            break;
        }

        // strip the trailing newline
        // strcspn returns the index of the first '\n'
        line[strcspn(line, "\n")] = '\0';

        // empty line (user just hit enter) — skip
        if (strlen(line) == 0) continue;

        // "exit" or "quit" — disconnect
        if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) break;

        // send the command encrypted
        if (tunnel_send(&t, (const uint8_t *)line, strlen(line)) < 0) {
            fprintf(stderr, "[client] send failed\n");
            break;
        }

        // receive the output encrypted
        uint8_t *output = NULL;
        uint32_t out_len = 0;
        if (tunnel_recv(&t, &output, &out_len) < 0) {
            fprintf(stderr, "[client] recv failed\n");
            break;
        }

        // fwrite, not printf — output may contain null bytes (binary data)
        fwrite(output, 1, out_len, stdout);
        free(output);
    }

    net_close(fd);
    return 0;
}
