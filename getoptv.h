#ifndef	GETOPTV_H
#define	GETOPTV_H	1

#include <stddef.h>		/* size_t */

#define OPTIONAL_VAL	0x00
#define NO_VAL		0x01
#define MULTI_VAL	0x02
#define REQUIRED_VAL	0x04
#define INT_VAL		0x08
#define OPT_TYPE(o)	((o).type & 0x03)

/* Descriptor of an option plus placeholders for option invocations count and
 * value/values specified for the option in those invocations. struct opt is
 * filled in by getopts() procedure. */
struct opt {
	const char key;	/* option name (key) */
	const int type;	/* option type (OPTIONAL_VAL etc) */
	int flags;	/* option flags */
	size_t cnt;	/* number of times the option was found on cmdline */
	size_t vcnt;	/* number of times non-NULL val was specified */

	/* 1st non-NULL value (parameter) specified for the option, or NULL.
	 *
	 * For non-MULTI_VAL option, val points into an original string from
	 * argv[] vector and thus calling free(x.val) is an error.
	 *
	 * For MULTI_VAL option, val is a shortcut to finding the 1st non-NULL
	 * value in vals[] array (which contains strdup()'s). Freeing it is
	 * also an error, because in this case it would be freed twice (one
	 * time via val, and another via some vals[i].
	 */
	char *val;
	int ival;	/* parsed INT_VAL value */

	/* Pointer to dynamically allocated array of values (or NULLs) for all
	 * of the MULTI_VAL option invocations. When cnt == 0, vals is also
	 * NULL (not allocated).
	 *
	 * For Nth invocation, vals[N] = optval ? strdup(optval) : NULL
	 *
	 * All elements in vals[] array and vals array itself are deallocated
	 * by freeoptv() procedure.
	 */
	char **vals;
	int *ivals;
};

int getoptv(struct opt *, char *[]);
void freeoptv(struct opt *);

#endif	/* ifndef GETOPTV_H */

/* vi:set sw=8 ts=8 noet tw=79: */
