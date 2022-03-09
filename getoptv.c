#include <stdlib.h>		/* malloc(), realloc(), strtol() */
#include <limits.h>		/* INT_MIN, INT_MAX */
#include <errno.h>		/* errno */
#include <stdio.h>		/* stderr, fprintf() */
#include <string.h>		/* strdup() */
#include "getoptv.h"		/* struct opt */

/**
 * Allocates/reallocates o->vals[] array to append strdup(val)/NULL to it and
 * increments o->cnt/vcnt on success.
 *
 * When append_multi_val() is unable to allocate additional memory or create a
 * duplicate of val string, it reports a warning to stderr and returns 0,
 * leaving o->cnt/vcnt unchanged.
 *
 * If failure occured after malloc/realloc suceeded, o->vals points to new
 * region of memory, and string pointers to previous values are copied there.
 *
 * @param	o	MULTI_VAL option descriptor to be updated;
 * @param	val	option's value (may be NULL if option was specified
 *			without parameter, e.g. "-h");
 * @param	arg	cmdline argument the option is part of. Only used for
 *			informational purposes in warning messages.
 *
 * @return	1 on success, 0 on failure
 */
static int append_multi_val(register struct opt *o, char *val,
		const char *arg) {
	register size_t vasz2, cnt2;
	char **vals2;
	int *ivals2;
	long l;
	char *endptr;

	if (o == NULL) return 0;

	if (o->type & REQUIRED_VAL && val == NULL) {
		fprintf(stderr, "WARNING: value required for"
			" \"-%.1s\", in \"%s\"\n", &o->key, arg);
		return 0;
	};

	cnt2 = o->cnt + 1;
	vasz2 = cnt2 * sizeof(char*);
	if (vasz2 / sizeof(char*) != cnt2) {
		/* integer overflow */
		fprintf(stderr, "WARNING: int overflow while"
			" appending \"-%.1s\"'s val, in \"%s\"\n",
			&o->key, arg);
		return 0;
	};
	/* Allocate additional memory for new string pointer: */
	if (o->vals == NULL) vals2 = malloc(vasz2);
	else vals2 = realloc(o->vals, vasz2);
	if (vals2 == NULL) {
		fprintf(stderr, "WARNING: %s(): %m, while"
			" appending \"-%.1s\"'s val, in \"%s\"\n",
			o->vals == NULL ? "malloc" : "realloc",
			&o->key, arg);
		return 0;
	};
	o->vals = vals2;
	/* Allocate additional memory for new ival: */
	if (o->ivals == NULL) ivals2 = malloc(vasz2);
	else ivals2 = realloc(o->ivals, vasz2);
	if (ivals2 == NULL) {
		fprintf(stderr, "WARNING: %s(): %m, while"
			" appending \"-%.1s\"'s ival, in \"%s\"\n",
			o->ivals == NULL ? "malloc" : "realloc",
			&o->key, arg);
		return 0;
	};
	o->ivals = ivals2;
	/* Append strdup(val) (or NULL) to o->vals[] array: */
	if (val == NULL) {
		o->vals[cnt2 - 1] = NULL;
		o->ivals[cnt2 - 1] = 0;
	} else if ((o->vals[cnt2 - 1] = strdup(val)) == NULL) {
		fprintf(stderr, "WARNING: strdup(): %m, while"
			" appending \"-%.1s\"'s val, in \"%s\"\n",
			&o->key, arg);
		return 0;
	} else {
		if (o->type & INT_VAL) {
			errno = 0;
			l = strtol(val, &endptr, 0);
			if (*val == '\0' || *endptr != '\0' || errno ||
					l > INT_MAX || l < INT_MIN) {
				fprintf(stderr, "WARNING: invalid int value"
					" for \"-%.1s\", in \"%s\"\n",
					&o->key, arg);
				return 0;
			};
			o->ivals[cnt2 - 1] = (int)l;
		};
		/* Store 1st non-NULL optvalue in o->val too: */
		if (o->val == NULL) {
			o->val = val;
			o->ival = o->ivals[cnt2 - 1];
		};
		o->vcnt++;
	};
	o->cnt = cnt2;
	return 1;
};

/**
 * Update .cnt/.vcnt (and .val/.vals[] if @val != NULL) fields of option
 * descriptor @o and @flags variable, if opt-val combination is valid.
 *
 * @param	o	opt descriptor to be updated
 * @param	flags	variable to be OR'ed with o->flags
 * @param	val	option's value (or NULL if none was given on cmdline)
 * @param	arg	cmdline argument the option is part of. Only used for
 *			informational purposes in warning messages.
 *
 * @return	1 on success, 0 if option is not valid or allocation errors
 *		encountered during vals[] update operation.
 */
static int update_opt_val(struct opt *o, int *flags, char *val,
		const char *arg) {
	char *endptr = NULL;
	long l;
	if (o == NULL) return 0;
	if (val == NULL) {
		if (o->type & REQUIRED_VAL) {
			fprintf(stderr, "WARNING: value required for"
				" \"-%.1s\", in \"%s\"\n", &o->key, arg);
			return 0;
		};
		if (OPT_TYPE(*o) == MULTI_VAL) {
			if (!append_multi_val(o, NULL, arg)) return 0;
			if (flags != NULL) *flags |= o->flags;
			return 1;
		};
		o->cnt++;
		if (flags != NULL) *flags |= o->flags;
		return 1;
	} else {
		if (OPT_TYPE(*o) == NO_VAL) {
			fprintf(stderr, "WARNING: value not allowed for"
				" \"-%.1s\", in \"%s\"\n", &o->key, arg);
			return 0;
		};
		if (OPT_TYPE(*o) == MULTI_VAL) {
			if (!append_multi_val(o, val, arg)) return 0;
			if (flags != NULL) *flags |= o->flags;
			return 1;
		};
		if (o->val != NULL) {
			fprintf(stderr, "WARNING: \"-%.1s\" is already set"
				" to \"%s\", ignoring \"%s\"\n",
				&o->key, o->val, arg);
			return 0;
		};
		if (o->type & INT_VAL) {
			errno = 0;
			l = strtol(val, &endptr, 0);
			if (*val == '\0' || *endptr != '\0' || errno ||
					l > INT_MAX || l < INT_MIN) {
				fprintf(stderr, "WARNING: invalid int value"
					" for \"-%.1s\", in \"%s\"\n",
					&o->key, arg);
				return 0;
			};
			o->ival = (int)l;
		};
		o->cnt++;
		o->val = val;
		o->vcnt = 1;
		if (flags != NULL) *flags |= o->flags;
		return 1;
	};
};

/* getoptv(struct opt *optv, char *argv[]):
 *
 * Scans argv[] starting from argv[1] until 1st non-option argument is found or
 * "--" arg explicitly indicates end of options. Fills in the supplied optv[]
 * vector with number of opt occurrences, opt values and error totals. Returns
 * index of first non-option argument in argv[] array.
 *
 * Option argument starts with a '-' followed by 1 or more key names, and
 * optionally by '=' sign and a value, e.g. "-h", "-e=", "-n=/run/netns/ns0".
 * Currently getoptv() only supports one-char option key names, which must be
 * different from "-" and "=".
 *
 * Options may be joined together, e.g. "-a", "-b", "-c" is equivalent to
 * "-abc". For such joined options, value can be given only to the last one,
 * e.g. "-abc=foo".
 *
 * @param	optv	array of opt descriptor structures terminated by
 *			descriptor with .key == '\0'
 * @param	argv	array of char pointers terminated by NULL.
 *
 * @return	0 on error or index of first non-option argument in argv[]
 *		array
 * @return	x.cnt	number of times the option with name x.key was
 *			successfully parsed
 * @return	x.val	pointer to the 1st value for the x.key or NULL if no
 *			value has been specified
 * @return	x.vals	array of values/NULLs for all occurences of option x,
 *			when x.type == MULTI_VAL
 *
 * When invalid option is encountered, getoptv() produces warning on stderr and
 * continues with next arg (it means that the rest of invalid opt arg is left
 * unprocessed, like e.g. "-z" part of "-xy-z" arg).
 *
 * Number of invalid options is recorded in .cnt field of optv[] terminator.
 * String pointer to the 1st argv containing invalid option is recorded in .val
 * field of optv[] terminator.
 */
int getoptv(struct opt *optv, char *argv[]) {
	register int i, optc;
	register char *p;
	register struct opt *o, *opt_inv;

	if (argv == NULL) {
		fprintf(stderr, "ERROR: getoptv() argv parameter is NULL\n");
		return 0;
	};
	if (argv[0] == NULL) {
		fprintf(stderr, "ERROR: getoptv() argv[0] is NULL\n");
		return 0;
	};
	if (optv == NULL) {
		fprintf(stderr, "ERROR: getoptv() optv parameter is NULL\n");
		return 0;
	};

	/* Find opt (terminator): */
	for (o = optv;; o++) {
		if (o->key == '\0')
			break;
	};
	opt_inv = o;	/* pointer to optv[] terminator */

	/* Process argv[]: */
	for (i = 1; argv[i] != NULL && argv[i][0] == '-' && argv[i][1] != '\0';
			i++) {
		/* If "--" arg is encountered, skip past it and finish option
		 * processing: */
		if (argv[i][1] == '-' && argv[i][2] == '\0') {
			i++;
			break;
		};
		/* Process opt chars in argv[i] after initial '-': */
		for (p = argv[i] + 1; *p != '\0'; p++) {
			/* '-' and '=' are illegal at this point: */
			if (*p == '-' || *p == '=') {
				fprintf(stderr, "WARNING: invalid opt"
					" \"-%.1s\" in \"%s\"\n",
					p, argv[i]);
				goto INVOPT;
			};
			/* search for *p character in optv[] array: */
			for (o = optv; o != opt_inv && o->key != *p; o++);
			/* check for opt syntax/semantics: */
			if (o->key != *p) {
				fprintf(stderr, "WARNING: unknown opt"
					" \"-%.1s\" in \"%s\"\n",
					p, argv[i]);
			} else if (p[1] == '=') {
				if (update_opt_val(o, &opt_inv->flags,
						p + 2, argv[i]))
					/* Go to next arg: */
					break;
			} else {
				if (update_opt_val(o, &opt_inv->flags,
						NULL, argv[i]))
					/* Go to next opt in the same arg: */
					continue;
			};
INVOPT:			/* The code below is executed only for errors: */
			opt_inv->cnt++;
			if (opt_inv->val != NULL) opt_inv->val = argv[i];
			break;	/* go to next arg */
		};
	};
#ifdef DEBUG
	{
		char *q = "\"", *a = argv[i];
		if (argv[i] == NULL) {q = ""; a = "NULL";};
		fprintf(stderr, "1st non-opt arg is argv[%i]: %s%s%s\n",
			i, q, a, q);
	}
#endif
	return i;
};

/* void freeoptv(struct opt *optv):
 *
 * Free memory occupied by copies of option values and .vals[] arrays of
 * MULTI_VAL options and reset all counters to 0.
 *
 * freeoptv() is only necessary if getoptv() was called with MULTI_VAL opt
 * descriptors; or if you want to scan for the same set of options multiple
 * times (e.g. vs different argv[]) with .cnt/.vals reset to zero.
 */
void freeoptv(struct opt *optv) {
	register struct opt *o;
	register char **p;

	if (optv == NULL) return;
	for (o = optv;; o++) {
#ifdef DEBUG
		fprintf(stderr, "-%.1s: type %i, flags %x, cnt %zu, vcnt %zu",
			o->key == '\0' ? "-" : &o->key,
			o->type, o->flags, o->cnt, o->vcnt);
		if (o->val == NULL)
			fprintf(stderr, ", val (nil)");
		else
			fprintf(stderr, ", val \"%s\"", o->val);
		fprintf(stderr, ", ival %i", o->ival);
#endif
		if (o->vals != NULL) {
#ifdef DEBUG
			fprintf(stderr, ", vals");
#endif
			/* Free optval copies: */
			for (int i = 0; i < o->cnt; i++) {
#ifdef DEBUG
				fprintf(stderr, " %s%s%s",
					o->vals[i] == NULL ? "" : "\"",
					o->vals[i] == NULL ? "(nil)" :
						o->vals[i],
					o->vals[i] == NULL ? "" : "\"");
				if (o->type & INT_VAL && o->vals[i] != NULL)
					fprintf(stderr, " (%i)", o->ivals[i]);
#endif
				free(o->vals[i]);
			};
			free(o->vals);
			o->vals = NULL;
#ifdef DEBUG
		} else {
			fprintf(stderr, ", vals (nil)");
#endif
		};
		if (o->ivals != NULL) {
#ifdef DEBUG
			fprintf(stderr, ", ivals");
			for (int i = 0; i < o->cnt; i++)
				fprintf(stderr, " %i", o->ivals[i]);
#endif
			free(o->ivals);
			o->ivals = NULL;
#ifdef DEBUG
		} else {
			fprintf(stderr, ", ivals (nil)");
#endif
		};
#ifdef DEBUG
		fprintf(stderr, "\n");
#endif
		o->cnt = 0;
		o->val = NULL;
		o->ival = 0;
		o->vcnt = 0;
		if (o->key == '\0') break;
	};
};

/* vi:set sw=8 ts=8 noet tw=79: */
