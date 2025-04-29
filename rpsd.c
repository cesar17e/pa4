#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include "network.h"

#define BUFLEN 256
#define QUEUE_SIZE 8
#define MAX_PLAYERS 100
#define MOVE_TIMEOUT_MS (5 * 60 * 1000)  // 5 minutes

static volatile int active = 1;
static char *active_names[MAX_PLAYERS];
static int active_count = 0;

void handle_sigint(int sig) {
    (void)sig;
    active = 0;
}

void install_handlers(void) {
    struct sigaction act;
    act.sa_handler = handle_sigint;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGINT, &act, NULL);
}

int register_name(const char *name) {
    if (active_count >= MAX_PLAYERS) return -1;
    for (int i = 0; i < active_count; i++) {
        if (strcmp(active_names[i], name) == 0) return -1;
    }
    active_names[active_count++] = strdup(name);
    return 0;
}

void unregister_name(const char *name) {
    for (int i = 0; i < active_count; i++) {
        if (strcmp(active_names[i], name) == 0) {
            free(active_names[i]);
            active_names[i] = active_names[--active_count];
            return;
        }
    }
}

ssize_t read_until_delim(int sock, char *buf, size_t maxlen) {
    size_t total = 0;
    while (total + 1 < maxlen) {
        ssize_t n = read(sock, buf + total, 1);
        if (n <= 0) return n;
        total += n;
        if (total >= 2 && buf[total-2] == '|' && buf[total-1] == '|') {
            buf[total] = '\0';
            return total;
        }
    }
    return -1;
}

int write_all(int sock, const void *buf, size_t count) {
    const char *p = buf;
    size_t remaining = count;
    while (remaining > 0) {
        ssize_t n = write(sock, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        remaining -= n;
    }
    return 0;
}

void send_msg(int sock, const char *msg) {
    if (write_all(sock, msg, strlen(msg)) < 0) {
        perror("[LOG] send_msg error");
    }
}

int validate_name(const char *name) {
    return (strchr(name, '|') == NULL);
}

int validate_move(const char *buf) {
    // buf includes trailing ||
    if (strncmp(buf, "M|", 2) != 0) return 0;
    size_t len = strlen(buf);
    if (len < 5) return 0; // must be at least M|X||
    // extract the move text
    char mv[16];
    size_t mv_len = len - 4; // exclude "M|" and "||"
    if (mv_len >= sizeof(mv)) return 0;
    memcpy(mv, buf + 2, mv_len);
    mv[mv_len] = '\0';
    return (strcmp(mv, "ROCK") == 0 || strcmp(mv, "PAPER") == 0 || strcmp(mv, "SCISSORS") == 0);
}

void handle_game(int p1, int p2) {
    char buf1[BUFLEN], buf2[BUFLEN];
    char *name1 = NULL, *name2 = NULL;
    int reg1 = 0, reg2 = 0;

    // Handshake phase
    if (read_until_delim(p1, buf1, BUFLEN) <= 0 || buf1[0] != 'P' || buf1[1] != '|') {
        send_msg(p2, "R|F|||"); close(p1); close(p2); return;
    }
    if (read_until_delim(p2, buf2, BUFLEN) <= 0 || buf2[0] != 'P' || buf2[1] != '|') {
        send_msg(p1, "R|F|||"); close(p1); close(p2); return;
    }

    // Extract and register names
    name1 = strdup(buf1 + 2); name1[strlen(name1)-2] = '\0';
    name2 = strdup(buf2 + 2); name2[strlen(name2)-2] = '\0';
    printf("[LOG] Players connected: %s vs %s\n", name1, name2);

    if (!validate_name(name1) || register_name(name1) < 0) {
        send_msg(p1, "R|L|Logged in||"); send_msg(p2, "R|W||");
        free(name1); free(name2); close(p1); close(p2); return;
    }
    reg1 = 1;
    if (!validate_name(name2) || register_name(name2) < 0) {
        send_msg(p2, "R|L|Logged in||"); send_msg(p1, "R|W||");
        unregister_name(name1); free(name1); free(name2); close(p1); close(p2); return;
    }
    reg2 = 1;

    // Send Wait
    printf("[LOG] Sent W|1|| to both players\n");
    send_msg(p1, "W|1||"); send_msg(p2, "W|1||");

    // Game loop
    while (active) {
        char out[BUFLEN];
        // Begin
        snprintf(out, BUFLEN, "B|%s||", name2); send_msg(p1, out);
        snprintf(out, BUFLEN, "B|%s||", name1); send_msg(p2, out);
        printf("[LOG] Sent begin messages\n");

        struct pollfd pfds[2] = {{p1, POLLIN, 0}, {p2, POLLIN, 0}};
        int moves = 0, timed_out = 0;
        char move1[BUFLEN] = {0}, move2[BUFLEN] = {0};

        while (moves < 2 && !timed_out) {
            int r = poll(pfds, 2, MOVE_TIMEOUT_MS);
            if (r < 0) break;
            if (r == 0) { timed_out = 1; break; }
            for (int i = 0; i < 2; i++) {
                if (pfds[i].revents & POLLIN) {
                    char *buf = (i == 0 ? move1 : move2);
                    if (read_until_delim(pfds[i].fd, buf, BUFLEN) <= 0) {
                        send_msg(i==0 ? p2 : p1, "R|F|||"); timed_out = 1; break;
                    }
                    if (!validate_move(buf)) {
                        int other = (i == 0 ? p2 : p1);
                        send_msg(pfds[i].fd, "R|L|Invalid||");
                        send_msg(other, "R|W||");
                        timed_out = 1; break;
                    }
                    printf("[LOG] Received move from %s: %s\n", i==0?name1:name2, buf);
                    moves++;
                    pfds[i].events = 0;
                }
            }
        }
        if (timed_out) break;

        // Result
        char m1 = move1[2], m2 = move2[2], r1, r2;
        if (m1 == m2) r1 = r2 = 'D';
        else if ((m1=='R'&&m2=='S')||(m1=='S'&&m2=='P')||(m1=='P'&&m2=='R')) r1='W', r2='L';
        else r1='L', r2='W';
        snprintf(out, BUFLEN, "R|%c|%c||", r1, m2); send_msg(p1, out);
        snprintf(out, BUFLEN, "R|%c|%c||", r2, m1); send_msg(p2, out);
        printf("[LOG] Results: %c for %s, %c for %s\n", r1, name1, r2, name2);

        // Continue/Quit handling
        char resp[BUFLEN];
        if (read_until_delim(p1, resp, BUFLEN) <= 0 || resp[0] == 'Q') {
            printf("[LOG] %s quit or disconnected\n", name1);
            send_msg(p2, "R|W||"); break;
        }
        if (resp[0] != 'C') {
            printf("[LOG] %s sent invalid response: %s\n", name1, resp);
            send_msg(p2, "R|W||"); break;
        }
        if (read_until_delim(p2, resp, BUFLEN) <= 0 || resp[0] == 'Q') {
            printf("[LOG] %s quit or disconnected\n", name2);
            send_msg(p1, "R|W||"); break;
        }
        if (resp[0] != 'C') {
            printf("[LOG] %s sent invalid response: %s\n", name2, resp);
            send_msg(p1, "R|W||"); break;
        }
        printf("[LOG] Both players requested rematch\n");
    }

    // Cleanup names and sockets
    if (reg1) unregister_name(name1);
    if (reg2) unregister_name(name2);
    free(name1); free(name2);
    close(p1); close(p2);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "Usage: %s <port>\n", argv[0]); exit(1);}    
    install_handlers();
    int listener = open_listener(argv[1], QUEUE_SIZE);
    if (listener < 0) exit(1);
    printf("[LOG] Listening on port %s\n", argv[1]);

    while (active) {
        struct sockaddr_storage client; socklen_t clen = sizeof(client);
        int p1 = accept(listener, (struct sockaddr*)&client, &clen);
        if (p1 < 0) continue;
        printf("[LOG] Accepted player1 socket %d\n", p1);
        int p2 = accept(listener, (struct sockaddr*)&client, &clen);
        if (p2 < 0) { close(p1); continue; }
        printf("[LOG] Accepted player2 socket %d\n", p2);
        handle_game(p1, p2);
    }

    // Free any remaining registered names
    for (int i = 0; i < active_count; i++) free(active_names[i]);
    printf("[LOG] Shutting down listener\n");
    close(listener);
    return 0;
}
