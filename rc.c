#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <string.h>
#include <poll.h>
#include "network.h"

#ifndef BUFLEN
#define BUFLEN 256
#endif

int main(int argc, char **argv)
{
    int sock, bytes;
    char buf[BUFLEN];

    if (argc != 3) {
	printf("Usage: %s host port\n", argv[0]);
	printf("       %s -l port\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "-l") == 0) {
	
	// listen for incoming connection
	int listen = open_listener(argv[2], 1);
	sock = accept(listen, NULL, NULL);
	close(listen);

    } else {

	// open socket to remote host
	sock = connect_inet(argv[1], argv[2]);
    }

    if (sock < 0) exit(EXIT_FAILURE);

    struct pollfd pfds[2];
    pfds[0].fd = STDIN_FILENO;
    pfds[1].fd = sock;
    pfds[0].events = POLLIN;
    pfds[1].events = POLLIN;

    for (;;) {
	int ready = poll(pfds, 2, -1);
	if (ready == -1) {
	    perror("poll");
	    exit(EXIT_FAILURE);
	}

	if (pfds[0].revents) {
	    bytes = read(STDIN_FILENO, buf, BUFLEN);
	    if (bytes < 1) break;

	    if (buf[bytes-1] == '\n') bytes--;
	    write(sock, buf, bytes);
	}
	if (pfds[1].revents) {
	    bytes = read(sock, buf, BUFLEN);
	    if (bytes < 1) {
		printf("Connection closed remotely\n");
		break;
	    }

	    struct iovec msg[] = {
		{ "In: >>", 6 },
		{ buf, bytes },
		{ "<<\n", 3 }};

	    writev(STDOUT_FILENO, msg, 3);

	}
    }
    puts("Closing\n");
    close(sock);

    return EXIT_SUCCESS;
}
