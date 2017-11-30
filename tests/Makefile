#amcsh Makefile
CFLAGS = -Wall
LDFLAGS = -lutil

all: vict

vict: vict.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
clean:
	-/bin/rm -f vict

.PHONY: clean
