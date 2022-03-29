#ifndef	PTY_H
#define	PTY_H	1

int open_pty(char **, int *);
int set_ctrl_tty(char *, int, uid_t, gid_t);

/* vi:set sw=8 ts=8 noet tw=79 ft=c: */
#endif	/* ifndef PTY_H */
