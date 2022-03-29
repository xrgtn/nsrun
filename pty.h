#ifndef	PTY_H
#define	PTY_H	1

/* NOTE:
 * #include <unistd.h> line below will define uid_t and gid_t types iff
 * _XOPEN_SOURCE is defined to 500 or greater and <unistd.h> hasn't been
 * included yet.
 *
 * If <unistd.h> has been included before "pty.h" and _XOPEN_SOURCE wasn't
 * properly defined prior to that, uid_t/gid_t won't be available.
 */
#include <unistd.h>	/* uid_t, gid_t */
#include <termios.h>	/* struct termios */

int open_pty(char **, int *);
int set_ctrl_tty(char *, int, uid_t, gid_t);
int init_tty_and_setraw(int, int, struct termios *);

/* vi:set sw=8 ts=8 noet tw=79 ft=c: */
#endif	/* ifndef PTY_H */
