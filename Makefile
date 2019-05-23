PROGS=	makepassdb passdbstat checkpass
SRCS=	passdb.c makepassdb.c passdbstat.c checkpass.c
CFLAGS=	-O -Wall -march=native
LIBS=	-lssl -lcrypto	# we use OpenSSL's bignum library

all: $(PROGS)
clean:
	rm -f $(PROGS) $(SRCS:.c=.o)

makepassdb: makepassdb.o passdb.o
	$(CC) $(LDFLAGS) -o $@ makepassdb.o passdb.o $(LIBS)

passdbstat: passdbstat.o passdb.o
	$(CC) $(LDFLAGS) -o $@ passdbstat.o passdb.o $(LIBS)

# XXX fix this to use OpenSSL's SHA-1 routines rather than FreeBSD libmd.
checkpass: checkpass.o passdb.o
	$(CC) $(LDFLAGS) -o $@ checkpass.o passdb.o $(LIBS) -lmd

$(SRCS:.c=.o): passdb.h
