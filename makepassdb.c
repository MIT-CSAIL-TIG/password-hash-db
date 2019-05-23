#include <sys/types.h>
#include <sys/mman.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "passdb.h"

int
main(int argc, char *const *argv)
{
	int rv;
	FILE *fp;
	char *dbname, *ext;
	const char *bufline;
	unsigned char *db_p;
	size_t len, lineno;

	if (argc != 2)
		errx(1, "must specify password list");

	fp = fopen(argv[1], "r");
	if (fp == NULL)
		err(1, "%s", argv[1]);
	lineno = 0;

	/* construct name of database */
	dbname = strdup(argv[1]);
	if (dbname == NULL)
		err(1, "strdup");
	ext = strrchr(dbname, '.');
	if (ext == NULL || strcmp(".txt", ext))
		errx(1, "expected password list to be a .txt file");
	len = strlcpy(ext, ".set", strlen(ext) + 1);
	assert(len == 4);

	rv = init_passdb(&db_p, dbname, O_RDWR | O_EXCL | O_CREAT | O_EXLOCK);
	if (rv)
		err(1, "%s", dbname);

	while ((bufline = fgetln(fp, &len)) != NULL) {
		++lineno;
		if (lineno % 100000 == 0) {
			sync_passdb(db_p);
			printf("%lu\r", lineno);
			fflush(stdout);
		}
		mark_passdb(db_p, bufline);
	}
	if (lineno > 0)
		printf("%lu done\n", lineno);
	fclose(fp);
	close_passdb(db_p);
	return (0);
}

