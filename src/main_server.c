//
// Created by biprarshi on 23/03/2026.
//
// clink server — listens for a client, does DH handshake,
// then receives encrypted commands and sends back their output.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"
#include "tunnel.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: clink_server <port>\n");
        return 1;
    }

    int port = atoi(argv[1]);

    // wait for a client to connect
    int fd = net_listen(port);
    if (fd < 0) return 1;

    // DH handshake
    Tunnel t;
    if (tunnel_handshake_server(&t, fd) < 0) {
        fprintf(stderr, "[server] handshake failed\n");
        net_close(fd);
        return 1;
    }

    // command loop
    while (1) {
        // receive the encrypted command from client
        uint8_t *cmd = NULL;
        uint32_t cmd_len = 0;
        if (tunnel_recv(&t, &cmd, &cmd_len) < 0) {
            // client disconnected or error — exit cleanly
            printf("[server] client disconnected\n");
            break;
        }

        // tunnel_recv gives raw bytes, not a C string, add \0 by realloc ing extra byte
        char *cmd_str = malloc(cmd_len + 1);
        memcpy(cmd_str, cmd, cmd_len);
        cmd_str[cmd_len] = '\0';
        free(cmd);

        printf("[server] running: %s\n", cmd_str);

        // popen runs the command through /bin/sh and gives us its stdout as a FILE*
        FILE *fp = popen(cmd_str, "r");
        free(cmd_str);
        if (!fp) {
            // command failed to start
            const char *err = "error: failed to run command\n";
            tunnel_send(&t, (const uint8_t *)err, strlen(err));
            continue;
        }

        // read all output from the command, grow the buffer as we read
        char *output = NULL;
        size_t total = 0;
        char tmp[4096];
        size_t n;
        while ((n = fread(tmp, 1, sizeof(tmp), fp)) > 0) {
            output = realloc(output, total + n);
            memcpy(output + total, tmp, n);
            total += n;
        }
        pclose(fp);

        // send the output back
        if (total > 0) {
            tunnel_send(&t, (const uint8_t *)output, total);
            free(output);
        } else {
            // no output for mkdir
            tunnel_send(&t, (const uint8_t *)"\n", 1);
        }
    }

    net_close(fd);
    return 0;
}
