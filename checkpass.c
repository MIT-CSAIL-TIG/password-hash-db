#include <sys/types.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <sha.h>
#include <string.h>
#include <unistd.h>

#include "passdb.h"

int
main(int argc, char *const *argv)
{
	SHA_CTX context;
	char *static_passwords[2] = { NULL, NULL };
	char *const *passwords = static_passwords;
	char hexdigest[41];
	unsigned char *db;
	int rv;

	if (argc < 2) {
		errx(1, "must specify at least the name of the database to check");
	}
	rv = init_passdb(&db, argv[1], O_RDONLY | O_SHLOCK);
	if (rv == -1)
		err(1, "%s", argv[1]);
	if (argc == 2) {
		static_passwords[0] = getpass("Password: ");
	} else {
		passwords = &argv[2];
	}

	rv = EXIT_FAILURE;
	while (*passwords != NULL) {
		SHA1_Init(&context);
		SHA1_Update(&context, *passwords, strlen(*passwords));
		SHA1_End(&context, hexdigest);
		if (check_passdb(db, hexdigest)) {
			printf("%s possibly in the database\n", hexdigest);
			rv = EXIT_SUCCESS;
		} else {
			printf("%s definitely not in the database\n", hexdigest);
		}
		passwords++;
	}
	return (rv);
}
