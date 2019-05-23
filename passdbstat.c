#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <x86intrin.h>

#include "passdb.h"

int
main(int argc, char *const *argv)
{
	unsigned char *buf;
	long long *llbuf;
	int rv, i;
	unsigned int population;
	
	if (argc != 2)
		errx(1, "must specify password database");
	rv = init_passdb(&buf, argv[1], O_RDONLY | O_SHLOCK);
	if (rv)
		err(1, "%s", argv[1]);
	llbuf = (long long *)buf;
	for (i = population = 0; i < DB_SIZE / sizeof(long long); i++) {
		population += _popcnt64(llbuf[i]);
	}
	printf("%u/%zu bits set (%.0f%%)\n", population, DB_BITS,
	       (double)population / DB_BITS * 100);
	close_passdb(buf);
	return (0);
}

		
