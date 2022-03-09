#ifndef	_UGIDS_H
#define	_UGIDS_H	1

#include <unistd.h>		/* uid_t, gid_t */
#include <pwd.h>		/* struct passwd */

struct ugids {
	uid_t ruid, euid, svuid, fsuid;
	gid_t rgid, egid, svgid, fsgid;
};

struct ugids getugids(void);
int setugids(struct ugids);
int ugids_eq(const struct ugids *, const struct ugids *);

struct passwb {
	struct	passwd pwd;
	size_t	bufsz;
	char	buf[];
};

struct passwb *getpwb(uid_t);

#endif /* ifndef _UGIDS_H */

/* vi:set sw=8 ts=8 noet tw=79: */
