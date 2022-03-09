#define _GNU_SOURCE	/* getresuid(), getresgid(), setresuid(), setresgid(),
			 * %m? */
#include <sys/types.h>	/* getpwuid_r() */
#include <sys/fsuid.h>	/* setfsuid() */
#include <unistd.h>	/* geteuid(), getegid(), setreuid(), setregid(),
			 * getresuid(), getresgid(), setresuid(), setresgid(),
			 * sysconf() */
#include <stddef.h>	/* offsetof, size_t, NULL */
#include <stdlib.h>	/* malloc(), free() */
#include <stdio.h>	/* stderr, fprintf() */
#include <errno.h>	/* errno, EPERM, ERANGE, EINVAL */
#include <pwd.h>	/* getpwuid_r(), fgetpwent_r() */
#include "uid_pw.h"

/* Helper getfsuid2()/getfsgid2()/setfsuid2()/setfsgid2() functions: */
static uid_t getfsuid2(void) {return (uid_t)setfsuid(-1);};
static gid_t getfsgid2(void) {return (gid_t)setfsgid(-1);};
static int setfsuid2(uid_t x) {
	setfsuid(x);
	if (getfsuid2() != x) {
		errno = EPERM;
		return -1;
	} else return 0;
};
static int setfsgid2(gid_t x) {
	setfsgid(x);
	if (getfsgid2() != x) {
		errno = EPERM;
		return -1;
	} else return 0;
};

/* Get current process' uids/gids. At least .ruid/.rgid and .euid/.egid fields
 * are always valid in the returned struct. */
struct ugids getugids(void) {
	int int_ret;
	struct ugids cr;
	int_ret = getresuid(&cr.ruid, &cr.euid, &cr.svuid);
	if (int_ret != 0) {
		fprintf(stderr, "WARNING: getresuid(): %m\n");
		cr.ruid = getuid();
		cr.euid = geteuid();
		cr.svuid = -1;
	};
	int_ret = getresgid(&cr.rgid, &cr.egid, &cr.svgid);
	if (int_ret != 0) {
		fprintf(stderr, "WARNING: getresgid(): %m\n");
		cr.rgid = getgid();
		cr.egid = getegid();
		cr.svgid = -1;
	};
	cr.fsgid = getfsgid2();
	return cr;
};

/* Set uids/gids. Return 0 on success, errno or 1 otherwise. */
int setugids(const struct ugids cr) {
	int e = 0;
	if (0 != setresuid(cr.ruid, cr.euid, cr.fsuid)) {
		e = errno ?: EPERM;
		fprintf(stderr, "WARNING: setresuid(%u, %u, %u): %m\n",
			cr.ruid, cr.euid, cr.fsuid);
		setuid(cr.ruid);
		seteuid(cr.euid);
	};
	if (0 != setfsuid2(cr.fsuid)) {
		e = errno ?: EPERM;
		fprintf(stderr, "WARNING: setfsuid2(%u): %m\n", cr.fsuid);
	};
	if (0 != setresgid(cr.rgid, cr.egid, cr.fsgid)) {
		e = errno ?: EPERM;
		fprintf(stderr, "WARNING: setresgid(%u, %u, %u): %m\n",
			cr.rgid, cr.egid, cr.fsgid);
		setgid(cr.rgid);
		setegid(cr.egid);
	};
	if (0 != setfsgid2(cr.fsgid)) {
		e = errno ?: EPERM;
		fprintf(stderr, "WARNING: setfsgid2(%u): %m\n", cr.fsgid);
	};
	errno = e;
	return e;
};

/* Compare ugids a and b, and return 1 if they are equal, 0 otherwise. */
int ugids_eq(const struct ugids *a, const struct ugids *b) {
	if (a == NULL && b == NULL) return 1;
	if (a == NULL || b == NULL) return 0;
	return	a->ruid == b->ruid &&	a->euid == b->euid &&
		a->svuid == b->svuid &&	a->fsuid == b->fsuid &&
		a->rgid == b->rgid &&	a->egid == b->egid &&
		a->svgid == b->svgid &&	a->fsgid == b->fsgid ?
		1 : 0;
};

/* scrsh.c:(.text+0x486): warning: Using 'getpwuid_r' in statically linked
 * applications requires at runtime the shared libraries from the glibc version
 * used for linking
 * Here is a wrapper around getpwuid_r: */
static int getpwuid_r2(uid_t uid, struct passwd *pwd, char *buf, size_t buflen,
		struct passwd **result) {
	struct passwd *pwe;
	FILE *pwf;
	char *src[5], **pdst[5], *ps, *pd;
	int int_ret = 0, i;

	if (result != NULL) *result = NULL;
	pwf = fopen("/etc/passwd", "r");
	if (pwf == NULL) goto EXIT1;
	while ((pwe = fgetpwent(pwf)) != NULL) {
		if (pwe->pw_uid != uid) continue;
		if (result != NULL) *result = pwd;
		if (pwd == NULL) break;
		pwd->pw_uid = pwe->pw_uid;
		pwd->pw_uid = pwe->pw_gid;
		pwd->pw_name = NULL;
		pwd->pw_passwd = NULL;
		pwd->pw_gecos = NULL;
		pwd->pw_dir = NULL;
		pwd->pw_shell = NULL;
		/* Copy 5 strings of pwe struct to buf. src[i] is i'th pwe
		 * string pointer: */
		src[0]  = pwe->pw_name;
		src[1]  = pwe->pw_passwd;
		src[2]  = pwe->pw_gecos;
		src[3]  = pwe->pw_dir;
		src[4]  = pwe->pw_shell;
		/* pdst[i] is a pointer to i'th pwd string pointer: */
		pdst[0] = &pwd->pw_name;
		pdst[1] = &pwd->pw_passwd;
		pdst[2] = &pwd->pw_gecos;
		pdst[3] = &pwd->pw_dir;
		pdst[4] = &pwd->pw_shell;
		for (pd = buf, i = 0; i < 5; i++) {
			if (src[i] == NULL) continue;
			/* If src[i] string is not NULL but buffer is, return
			 * ERANGE (Insufficient buffer space supplied): */
			if (buf == NULL) {
				int_ret = ERANGE;
				goto EXIT0;
			};
			ps = src[i];
			/* Tentatively set i'th pwd string pointer to pd (next
			 * free position in buffer). src[i] will be copied to
			 * buf starting from there: */
			*pdst[i] = pd;
			while (pd < buf + buflen && (*pd++ = *ps++) != '\0');
			/* If src[i] string hasn't been fully copied, revert
			 * *pdst[i] back to NULL and return ERANGE: */
			if (ps == src[i] || ps[-1] != '\0') {
				*pdst[i] = NULL;
				int_ret = ERANGE;
				goto EXIT0;
			};
		};
		break;
	};
	goto EXIT0;
EXIT1:	int_ret = errno;
EXIT0:	if (pwf != NULL) fclose(pwf);
	return int_ret;
};

/* Find pwent for the given uid and return it in struct passwb. */
struct passwb *getpwb(uid_t uid) {
	long ret_long;
	int int_ret;
	size_t sz, bufoffs = offsetof(struct passwb, buf);
	struct passwb *pwb;
	struct passwd *pwdr = NULL;

	/* Determine size for pwd strings' buffer: */
	ret_long = sysconf(_SC_GETPW_R_SIZE_MAX);
	sz = (ret_long > 0) ? ret_long : 4096 - bufoffs;

	/* Try to allocate: */
	pwb = malloc(sz + bufoffs);
	if (pwb == NULL) {
		int_ret = errno;	/* store errno */
		fprintf(stderr, "WARNING: malloc(%zu): %m\n", sz + bufoffs);
		errno = int_ret;	/* restore errno */
		return NULL;
	};
	pwb->bufsz = sz;

	/* Get user's pwd struct and strings: */
	int_ret = getpwuid_r2(uid, &pwb->pwd, pwb->buf, pwb->bufsz, &pwdr);
	if (int_ret != 0) {
		errno = int_ret;	/* getpwuid_r/r2() actually returns errno */
		fprintf(stderr, "WARNING: getpwuid_r2(%u): %m\n", uid);
		errno = int_ret;	/* restore errno */
	} else if (pwdr == NULL) {
		fprintf(stderr, "WARNING: no pwd record for uid %u\n", uid);
		errno = EINVAL;		/* "invalid" uid, sort of */
	};

	return pwb;
};

/* vi:set sw=8 ts=8 noet tw=79: */
