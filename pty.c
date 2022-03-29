/*!
 * \fn		pty.c
 *
 * \brief	Correct usage of ptm/pts.
 *
 * In Linux kernel, ptm and pts devices are represented by the same `struct
 * tty_struct` type; and pair of related ptm/pts structures are linked by
 * .link (->link) member pointers, i.e:
 *
 *	ptm->link == pts && pts->link == ptm
 *
 * Differences lay in their driver->subtype: PTY_TYPE_MASTER for ptm and
 * PTY_TYPE_SLAVE for pts, in termios parameters and a few other things (this
 * is true for both legacy BSD-style PTY's and for Unix98-style ones).
 *
 * Typically, ptm/pts pair is regarded as pty/tty or tty/real_tty in Linux
 * code. For example, looking at tty_pair_get_tty() and tty_ioctl() functions
 * in drivers/tty/tty_io.c, and tty_mode_ioctl() in drivers/tty/tty_ioctl.c,
 *
 *	static struct tty_struct *tty_pair_get_tty(struct tty_struct *tty)
 *	{
 *		if (tty->driver->type == TTY_DRIVER_TYPE_PTY &&
 *		    tty->driver->subtype == PTY_TYPE_MASTER)
 *			tty = tty->link;
 *		return tty;
 *	}
 *	... tty_ioctl():
 *		real_tty = tty_pair_get_tty(tty);
 *		...
 *		switch (cmd) {
 *		case TIOCSTI:
 *			return tiocsti(tty, p);
 *		case TIOCGWINSZ:
 *			return tiocgwinsz(real_tty, p);
 *		case TIOCSWINSZ:
 *			return tiocswinsz(real_tty, p);
 *		...
 *		case TIOCGPTPEER:
 *			return ptm_open_peer(file, tty, (int)arg);
 *		...
 *	... tty_mode_ioctl():
 *		case TCSETSW2:
 *			return set_termios(real_tty, p, TERMIOS_WAIT);
 *		case TCSETS2:
 *			return set_termios(real_tty, p, 0);
 *		...
 *
 * we can see that:
 *
 * 1.	of a ptm/pts pair, _slave_ part is considered a "real" tty device.
 *
 * 2.	ioctl() handler silently substitutes pts when called with ptm file
 *	descriptor for IOCGWINSZ, TIOCSWINSZ, TCSETSx and TCGETSx operations,
 *	so for most userspace code "it just works" and not worth distinct
 *	treatment.
 *
 * Reading man ioctl_tty and the Linux kernel sources mentioned above (plus
 * drivers/tty/pty.c), the conclusion is as follows:
 *
 * ptm/pts pair represents a slave TTY device, "owned" by non-TTY master one.
 *
 * Thus, "ideologically correct" code SHOULD direct all termios and winsize
 * operations to pts file descriptor; while ptm fd MUST be used for sending
 * "input" to pts, receiving output from pts, and for issuing ptm-specific
 * ioctl's like TIOCPKT, TIOCGPKT, TIOCSPTLCK, TIOCGPTLCK, TIOCSIG, TIOCGPTN
 * and TIOCGPTPEER (these ioctl's won't work on pts BTW).
 */

#define _XOPEN_SOURCE	600	/* posix_openpt(), grantpt(), unlockpt(),
				 * ptsname(), uid_t, gid_t */
#define _POSIX_C_SOURCE	199309L	/* fchmod() */
#include <stddef.h>		/* NULL */
#include <sys/stat.h>		/* fchmod(), mode_t */
#include <sys/ioctl.h>		/* ioctl(), TIOCGWINSZ, TIOCSWINSZ */
#include <fcntl.h>		/* O_RDWR, O_NOCTTY, fcntl(), F_SETFD,
				 * FD_CLOEXEC, F_SETFL, O_NONBLOCK */
#include <errno.h>		/* errno, ENOTTY, EINTR, ECHILD */
#include <unistd.h>		/* STDIN/OUT/ERR_FILENO, close(), fchown(),
				 * dup2(), setsid(), uid_t, gid_t, pid_t */
#include <stdlib.h>		/* free(), posix_openpt(), grantpt(),
				 * unlockpt(), ptsname() */
#include <termios.h>		/* struct termios, struct winsize,
				 * tcgetattr(), tcsetattr(), TCSANOW */
#include <stdio.h>		/* fprintf(), stderr */
#include <string.h>		/* strdup() */
#include "pty.h"

#define warn(...) do {						\
		int e = errno;					\
		fprintf(stderr, "WARNING: " __VA_ARGS__);	\
		fflush(stderr);					\
		errno = e;					\
	} while (0)

/*!
 * \brief	Open and setup pseudo-terminal master and optionally open
 *		corresponding pty slave device.
 *
 * Open pty master device, do grantpt(), unlockpt(), optionally get slave pty
 * device name and open it.
 *
 * \param[out]	ptsfn	If \p ptsfn is non-NULL, on return \p *ptsfn will point
 *			to dynamically allocated string holding slave pty
 *			device name.
 *
 * \param[out]	ptsfd	If \p ptsfd is not NULL, on return \p *ptsfd will hold
 *			open pts file descriptor. If ptsfd is NULL, open_pty()
 *			won't try open pts device. If both ptsfn and ptsfd are
 *			NULL, open_pty() won't call ptsname()/strdup() too.
 *
 * \return	open file descriptor of pty master device (/dev/ptmx) on
 *		success, -1 on error (with errno of main cause of failure
 *		preserved [and optionally some warnings printed on stderr]).
 *
 * \sa		man 3p posix_openpt
 */
int open_pty(char **ptsfn, int *ptsfd) {
	int ptmxfd, e;

	/* Open /dev/ptmx The-POSIX-Way (see Tcl/Expect's source code if you're
	 * interested what other ways there are): */
	ptmxfd = posix_openpt(O_RDWR | O_NOCTTY);
	if (ptmxfd == -1) {
		warn("posix_openpt(RW/NOCTTY): %m\n");
		goto EXIT1;
	};
	if (grantpt(ptmxfd) == -1) {
		warn("grantpt(%i): %m\n", ptmxfd);
		goto EXIT2;
	};
	if (unlockpt(ptmxfd) == -1) {
		warn("unlockpt(%i): %m\n", ptmxfd);
		goto EXIT2;
	};

	if (ptsfn == NULL) {
		if (ptsfd == NULL) {
			/* If caller is not interested in pts filename nor its
			 * file descriptor, return open ptmx file descriptor
			 * only: */
			return ptmxfd;
		} else /* ptsfd != NULL */ {
			int fd;
#ifdef	TIOCGPTPEER
			fd = ioctl(ptmxfd, TIOCGPTPEER, O_RDWR | O_NOCTTY);
			if (fd == -1) {
				warn("ioctl(%i, TIOCGPTPEER): %m\n", ptmxfd);
				goto EXIT2;
			};
#else	/* !defined(TIOCGPTPEER) */
			char *p = ptsname(ptmxfd);
			if (p == NULL) {
				warn("ptsname(%i): %m\n", ptmxfd);
				goto EXIT2;
			};
			fd = open(p, O_RDWR | O_NOCTTY);
			if (fd == -1) {
				warn("open(\"%s\", RW/NOCTTY): %m\n", p);
				goto EXIT2;
			};
#endif	/* !defined(TIOCGPTPEER) */
			*ptsfd = fd;
			return ptmxfd;
		};
	} else /* ptsfn != NULL */ {
		char *p, *fn;
		p = ptsname(ptmxfd);
		if (p == NULL) {
			warn("ptsname(%i): %m\n", ptmxfd);
			goto EXIT2;
		};
		fn = strdup(p);
		if (fn == NULL) {
			warn("strdup(\"%s\"): %m\n", p);
			goto EXIT2;
		};
		if (ptsfd == NULL) {
			*ptsfn = fn;
			return ptmxfd;
		} else /* ptsfd != NULL */ {
			int fd = open(fn, O_RDWR | O_NOCTTY);
			if (fd == -1) {
				warn("open(\"%s\", RW/NOCTTY): %m\n", fn);
				goto EXIT3;
			};
			*ptsfn = fn;
			*ptsfd = fd;
			return ptmxfd;
		};
EXIT3:		e = errno;
		free(fn);
		errno = e;
	};
EXIT2:	e = errno;
	if (close(ptmxfd) == -1)
		warn("close(ptmx): %m\n");
	errno = e;
EXIT1:	return -1;
};

/*!
 * \brief	Open/setup controlling tty (of the calling process).
 *
 * Open specified tty device file \p ttyfn (if ttyfd is not valid), change \p
 * ttyfn/ttyfd's owner to \p u:g and mode to 0600, start new session, set \p
 * ttyfn/ttyfd as controlling terminal and reopen stdin/out/err to it.
 *
 * \param	ttyfn	tty defice filename, or NULL
 * \param	ttyfd	open file descriptor of tty defice, or -1. At least one
 *			of \p ttyfn or \p ttyfd must be valid, otherwise -1 will
 *			be returned with errno set to EINVAL.
 * \param	u	uid to set as tty owner user
 * \param	g	gid to set as tty owner group
 *
 * \return	0 on success, -1 on error (with errno of main cause of failure
 *		preserved [and optionally some warnings printed on stderr]).
 *
 * \sa		man 3 login_tty
 */
int set_ctrl_tty(char *ttyfn, int ttyfd, uid_t u, gid_t g) {
	int ret = -1;
	int fd;

	if (ttyfn == NULL && ttyfd == -1) {
		warn("set_ctrl_tty(): both ttyfn and ttyfd not valid\n");
		errno = EINVAL;
		goto EXIT0;
	};

	if (ttyfd != -1) {
		fd = ttyfd;
	} else {
		fd = open(ttyfn, O_RDWR | O_NOCTTY);
		if (fd == -1) {
			warn("open(\"%s\", RW/NOCTTY): %m\n", ttyfn);
			goto EXIT0;
		};
	};
	if (fchown(fd, u, g) == -1) {
		warn("fchown(%i, %u, %u): %m\n", fd, (unsigned)u, (unsigned)g);
		goto EXIT1;
	};
	if (fchmod(fd, 0600) == -1) {
		warn("fchmod(%i, 0600): %m\n", fd);
		goto EXIT1;
	};
	if (setsid() == (pid_t)-1) {
		warn("setsid(): %m\n");
		goto EXIT1;
	};
	if (ioctl(fd, TIOCSCTTY, 0) == -1) {
		warn("ioctl(%i, TIOCSCTTY): %m\n", fd);
		goto EXIT1;
	};
	if (fd != STDIN_FILENO && dup2(fd, STDIN_FILENO) == -1) {
		warn("dup2(%i, %i): %m\n", fd, STDIN_FILENO);
		goto EXIT1;
	};
	if (fd != STDOUT_FILENO && dup2(fd, STDOUT_FILENO) == -1) {
		warn("dup2(%i, %i): %m\n", fd, STDOUT_FILENO);
		goto EXIT1;
	};
	if (fd != STDERR_FILENO && dup2(fd, STDERR_FILENO) == -1) {
		warn("dup2(%i, %i): %m\n", fd, STDERR_FILENO);
		goto EXIT1;
	};
	ret = 0;
EXIT1:	if (ttyfd == -1) {
		int e = errno;
		if (close(fd) == -1)
			warn("close(%i): %m\n", fd);
		errno = e;
	};
EXIT0:	return ret;
};

static int setrawmode(struct termios *t) {
	if (t == NULL) {
		errno = EINVAL;
		return -1;
	};
	t->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
		| INLCR | IGNCR | ICRNL | IXON);
	t->c_oflag &= ~OPOST;
	t->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	t->c_cflag &= ~(CSIZE | PARENB);
	t->c_cflag |= CS8;
	return 0;
};

/*!
 * \brief	Init fd's termios and winsize from rfd (or defaults), and
 *		optinally set rfd to raw mode.
 *
 * If rfd is not a tty, use default termios/winsize and don't switch to raw.
 * Default termios is kernel's default plus IUTF8 and VERASE=^H.
 * Default winsize is 80x24.
 *
 * \param	fd		tty to be initialized (typically slave PTY)
 * \param	rfd		"reference" tty device (typically STDIN)
 * \param	termios_p[out]	if termios_p is NULL, don't switch to raw mode.
 *				Otherwise, save original mode there before
 *				switching to raw.
 *
 * \return	1 if copy/init succeded and raw mode set,
 *		0 on success otherwise,
 *		-1 on error (with errno of main cause of failure preserved [and
 *		optionally some warnings printed on stderr]).
 */
int init_tty_and_setraw(int fd, int rfd, struct termios *termios_p) {
	struct termios tios0;
	struct winsize winsz0;
	int tios0ref = 0;

	/* Get/init tios0 for fd: */
	if (tcgetattr(rfd, &tios0) == 0) {
		tios0ref = 1;
	} else if (errno != ENOTTY) {
		warn("tcgetattr(%i): %m\n", rfd);
		return -1;
	} else if (tcgetattr(fd, &tios0) == 1) {
		warn("tcgetattr(%i): %m\n", fd);
		return -1;
	} else {
		tios0.c_iflag |= IUTF8;
		tios0.c_cc[VERASE] = '\010';	/* ^H */
	};
	/* Get/init winsz0 for fd: */
	if (ioctl(rfd, TIOCGWINSZ, &winsz0) == -1) {
		if (errno != ENOTTY) {
			warn("get winsize(%i): %m\n", rfd);
			return -1;
		};
		/* set "default" winsize of 80x24: */
		memset(&winsz0, 0, sizeof(winsz0));
		winsz0.ws_col = 80;
		winsz0.ws_row = 24;
	};

	/* Set fd's termios: */
	if (tcsetattr(fd, TCSANOW, &tios0) == -1) {
		warn("tcsetattr(%i): %m\n", fd);
		return -1;
	};
	/* Set fd's winsize: */
	if (ioctl(fd, TIOCSWINSZ, &winsz0) == -1) {
		warn("set winsize(%i): %m\n", fd);
		return -1;
	};

	/* If switch to raw isn't requested or rfd is not a tty, return. */
	if (termios_p == NULL || !tios0ref)
		return 0;

	memcpy(termios_p, &tios0, sizeof(tios0));
	setrawmode(&tios0);
	if (tcsetattr(rfd, TCSANOW, &tios0) == -1) {
		warn("tcsetattr(%i): %m\n", rfd);
		return -1;
	};
	return 1;
};

/* vi:set sw=8 ts=8 noet tw=79: */
