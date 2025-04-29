# Default target: build both server and client
all: rpsd rc

# Compiler and flags
CC = gcc
CFLAGS = -g -Wall -std=c99 -fsanitize=address,undefined -pthread

# Network helper
NETWORK_OBJS = network.o

# Client (rc)
RC_OBJS = rc.o $(NETWORK_OBJS)
rc: $(RC_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Server (rpsd)
RPSD_OBJS = rpsd.o $(NETWORK_OBJS)
rpsd: $(RPSD_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Pattern rule for .o files
%.o: %.c network.h
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up binaries and objects
clean:
	rm -f *.o rpsd rc

.PHONY: all clean rpsd rc
