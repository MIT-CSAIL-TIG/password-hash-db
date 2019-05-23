/*
 * Bloom-filter database for bad passwords
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "passdb.h"

static BN_CTX *ctx;
static BN_ULONG prime_vals[] = PRIME_VALS;
static BIGNUM primes[NPRIMES], modulus;

int
init_passdb(unsigned char **bufp, const char *dbname, int mode)
{
	int fd;
	unsigned char *buf;

	ctx = BN_CTX_new();
	for (int i = 0; i < NPRIMES; i++) {
		BN_init(&primes[i]);
		BN_set_word(&primes[i], prime_vals[i]);
	}
	BN_init(&modulus);
	BN_set_word(&modulus, DB_BITS);

	fd = open(dbname, mode, 0666);
	if (fd == -1)
		return -1;
	if (fd & O_CREAT) {
		if (ftruncate(fd, DB_SIZE) == -1)
			return -1;
	}
	int prot = PROT_READ;
	if (mode & O_RDWR)
		prot |= PROT_WRITE;
	buf = mmap(NULL, DB_SIZE, prot, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		int sverrno = errno;
		close(fd);
		errno = sverrno;
		return -1;
	}
	close(fd);
	*bufp = buf;
	return 0;
}

#define CHECKBIT(buf, index) (buf[index / CHAR_BIT] & 1 << (index % CHAR_BIT))
#define SETBIT(buf, index) (buf[index / CHAR_BIT] |= 1 << (index % CHAR_BIT))

void
mark_passdb(unsigned char *db, const char *hexdigest)
{
	BIGNUM *number, temp;
	BN_ULONG val;
	int rv, i;

	number = NULL;
	rv = BN_hex2bn(&number, hexdigest);
	if (rv != 2*HASHLEN) {
		warnx("unable to parse digest %s", hexdigest);
		return;
	}

	for (i = 0; i < NPRIMES; i++) {
		BN_init(&temp);
		BN_mod_mul(&temp, number, &primes[i], &modulus, ctx);
		val = BN_get_word(&temp);
		BN_free(&temp);
		assert(val < DB_BITS);
		SETBIT(db, val);
	}

	BN_free(number);
}

int
check_passdb(unsigned char *db, const char *hexdigest)
{
	BIGNUM *number, temp;
	BN_ULONG val;
	int rv, i, ispresent;

	number = NULL;
	rv = BN_hex2bn(&number, hexdigest);
	if (rv != 2*HASHLEN) {
		warnx("unable to parse digest %s", hexdigest);
		return (0);
	}

	for (i = 0, ispresent = 1; i < NPRIMES; i++) {
		BN_init(&temp);
		BN_mod_mul(&temp, number, &primes[i], &modulus, ctx);
		val = BN_get_word(&temp);
		BN_free(&temp);
		assert(val < DB_BITS);
		ispresent = ispresent && CHECKBIT(db, val);
	}

	BN_free(number);
	return (ispresent);
}

void
sync_passdb(unsigned char *buf)
{
	msync(buf, DB_SIZE, MS_ASYNC); /* errors necessarily ignored */
}

void close_passdb(unsigned char *buf)
{
	munmap(buf, DB_SIZE);
	for (int i = 0; i < NPRIMES; i++) {
		BN_free(&primes[i]);
	}
	BN_free(&modulus);
	BN_CTX_free(ctx);
}
