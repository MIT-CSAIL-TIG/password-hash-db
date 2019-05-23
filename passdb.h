/*
 * Bloom-filter database for bad password screening.
 */

#ifndef passdb_h_included
#define	passdb_h_included 1

#include <openssl/bn.h>

#define	HASHLEN 20		/* it's a 20-byte SHA-1 hash */

#define DB_SIZE (size_t)268435456	   /* 16 MB database */
#define	DB_BITS (DB_SIZE*CHAR_BIT)	 /* number of bits in the database */

#define PRIME_VALS \
	{ 137438953447ul, 9141833383481485409ul, 4530053345826294137ul }
#define	NPRIMES	3

extern int init_passdb(unsigned char **, const char *, int mode);
extern void mark_passdb(unsigned char *, const char *);
extern int check_passdb(unsigned char *, const char *);
extern void sync_passdb(unsigned char *);
extern void close_passdb(unsigned char *);

#endif	/* passdb_h_included */
