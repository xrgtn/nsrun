/*!
 * Prototype code for pty proxy (a la `su -P`), to be incorporated into nsrun
 * later.
 *
 * \version	1.0
 * \author	xrgtn
 * \date	2022
 */

#define _XOPEN_SOURCE	600	/* posix_openpt(), grantpt(), unlockpt(),
				 * ptsname() */
#define _POSIX_C_SOURCE	199309L	/* sigaction(), siginfo_t */
#include <stddef.h>		/* NULL, EXIT_SUCCESS, EXIT_FAILURE */
#include <unistd.h>		/* fork(), STDIN_FILENO, close(), fchown(),
				 * dup2(), STDOUT_FILENO, STDERR_FILENO,
				 * setsid(), write() */
#include <stdlib.h>		/* free(), posix_openpt(), grantpt(),
				 * unlockpt(), ptsname() */
#include <fcntl.h>		/* O_RDWR, O_NOCTTY, fcntl(), F_SETFD,
				 * FD_CLOEXEC, F_SETFL, O_NONBLOCK */
#include <stdio.h>		/* fprintf(), stderr */
#include <errno.h>		/* errno, ENOTTY, EINTR, ECHILD */
#include <string.h>		/* strdup(), memcpy() */
#include <termios.h>		/* struct termios, struct winsize,
				 * tcgetattr(), tcsetattr(), TCSANOW */
#include <sys/wait.h>		/* wait(), waitpid(), WNOHANG, WIFEXITED(),
				 * WEXITSTATUS(), WIFSIGNALED(), WTERMSIG() */
#include <fcntl.h>		/* fcntl(), F_SETFL, O_NONBLOCK */
#include <sys/ioctl.h>		/* ioctl(), TIOCGWINSZ, TIOCSWINSZ */
#include <poll.h>		/* poll(), struct pollfd, nfds_t, POLLIN,
				 * POLLOUT */
#include <sys/stat.h>		/* fchmod() */
#include <signal.h>		/* sigaction(), siginfo_t, SIGCHLD, SIGWINCH,
				 * SIGALRM, SIGTERM, SIGINT, SIGQUIT,
				 * struct sigaction, SA_SIGINFO, CLD_EXITED,
				 * CLD_KILLED, CLD_DUMPED etc. */

#define warn(...) do {						\
		int e = errno;					\
		fprintf(stderr, "WARNING: " __VA_ARGS__);	\
		fflush(stderr);					\
		errno = e;					\
	} while (0)

int sigpipefd[2] = {-1, -1};
const int sigv[] = {SIGCHLD, SIGWINCH, SIGALRM, SIGTERM, SIGINT, SIGQUIT,
	SIGHUP, SIGABRT, SIGPWR, SIGCONT, SIGUSR1, SIGUSR2};
const int sigc = sizeof(sigv) / sizeof(*sigv);
sig_atomic_t sigpipe_fail = 0;

/* essential siginfo */
struct siginfo_e {
	int	se_signo;
	int	se_code;
	pid_t	se_pid;
};

void sigpipewriter(int sig, siginfo_t *info, void *ucontext) {
	struct siginfo_e se;
	ssize_t ssz;
	int errno0 = errno;
	se.se_signo	= sig;
	se.se_code	= info->si_code;
	se.se_pid	= info->si_pid;
	/* man 7 pipe:
	 * POSIX.1 says that write(2)s of less than PIPE_BUF bytes must be
	 * atomic: the output data is written to the pipe as a contiguous
	 * sequence. Writes of more than PIPE_BUF bytes may be nonatomic:
	 * the kernel may interleave the data with data written by other
	 * processes. POSIX.1 requires PIPE_BUF to be at least 512 bytes...
	 * ...
	 * O_NONBLOCK enabled, n <= PIPE_BUF
	 *	If there is room to write n bytes to the pipe, then write(2)
	 *	succeeds immediately, writing all n bytes; otherwise write(2)
	 *	fails, with errno set to EAGAIN.
	 */
	ssz = write(sigpipefd[1], &se, sizeof(se));
	if (ssz != sizeof(se))
		sigpipe_fail = 1;
	/* errno
	 *	Fetching and setting the value of errno is async-signal-safe
	 *	provided that the signal handler saves errno on entry and
	 *	restores its value before returning. */
	errno = errno0;
};

/*!
 * In Linux kernel, ptm and pts devices are represented by the same `struct
 * tty_struct` type; and pair of related ptm/pts structures are linked by
 * .link (->link) member pointers, i.e:
 *
 *	ptm->link == pts && pts->link == ptm
 *
 * Differences lay in their driver->subtype: PTY_TYPE_MASTER for ptm and
 * PTY_TYPE_SLAVE for pts, in termios parameters and a few other things (this
 * is true for both legacy BSD-style ptm/pts and for Unix98-style ptm/pts).
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
 *	descriptor for IOCGWINSZ, TIOCSWINSZ, TCSETSx and TCGETSx operations.
 *
 * Reading man ioctl_tty and the Linux kernel sources mentione above (plus
 * drivers/tty/pty.c), the conclusion is as follows:
 *
 * ptm/pts pair represents a slave tty device, "owned" by non-tty master.
 * All termios and winsize operations should be directed to pts (although on
 * Linux they work against ptm all the same), while ptm is to be used for
 * sending "input" to and receiving "output" from pts, ans issuing
 * ptm-specific ioctls TIOCPKT, TIOCGPKT, TIOCSPTLCK, TIOCGPTLCK, TIOCSIG,
 * TIOCGPTN and TIOCGPTPEER.
 */

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
 * Open specified tty device file \p ptsfn (if ptsfd is not valid), change \p
 * ptsfn/ptsfd's owner to \p u:g and mode to 0600, start new session, set \p
 * ptsfn/ptsfd as controlling terminal and reopen stdin/out/err to it.
 *
 * \param	ptsfn	tty defice filename, or NULL
 * \param	ptsfd	open file descriptor of tty defice, or -1. At least one
 *			of \p ptsfn or \p ptsfd must be valid, otherwize -1 will
 *			be returned with errno set to EINVAL.
 * \param	u	uid to set as tty owner user
 * \param	g	gid to set as tty owner group
 *
 * \return	0 on success, -1 on error (with errno of main cause of failure
 *		preserved [and optionally some warnings printed on stderr]).
 *
 * \sa		man 3 login_tty
 */
int set_ctrl_tty(char *ptsfn, int ptsfd, uid_t u, gid_t g) {
	int ret = -1;
	int fd;

	if (ptsfn == NULL && ptsfd == -1) {
		warn("set_ctrl_tty(): both ptsfn and ptsfd not valid\n");
		errno = EINVAL;
		goto EXIT0;
	};

	if (ptsfd != -1) {
		fd = ptsfd;
	} else {
		fd = open(ptsfn, O_RDWR | O_NOCTTY);
		if (fd == -1) {
			warn("open(\"%s\", RW/NOCTTY): %m\n", ptsfn);
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
EXIT1:	if (ptsfd == -1) {
		int e = errno;
		if (close(fd) == -1)
			warn("close(%i): %m\n", fd);
		errno = e;
	};
EXIT0:	return ret;
};

void restore_sigaction_dfl(void) {
	struct sigaction sa, sa0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	for (int i = 0; i < sigc; i++) {
		if (sigaction(sigv[i], &sa, &sa0) == -1) {
			warn("sigaction SIG_%i DFL: %m\n", sigv[i]);
		};
	};
};

/*!
 * Close pair of pipe file descriptors.
 *
 * \param	sigpipefd[in]	pointer to array of open pipe's file
 *				descriptors.
 *
 * \return	0 on success, -1 on error
 */
int close_sigpipe(int sigpipefd[2]) {
	int e = 0;
	if (sigpipefd == NULL) {
		errno = EINVAL;
		return -1;
	};
	for (int i = 1; i >= 0; i--) {
		if (close(sigpipefd[i]) == -1) {
			e = errno;
			warn("close(sigpipefd[%i]): %m\n", i);
		};
	};
	if (e != 0) {
		errno = e;
		return -1;
	} else {
		return 0;
	};
};

/*!
 * Open/connect pair of pipe file descriptors, set FD_CLOEXEC flag on both and
 * O_NONBLOCK on write end of pipe.
 *
 * \param	sigpipefd[out]	pointer to array of 2 integers into which
 *				open file descriptors for read end of pipe
 *				\c (sigpipefd[0]) and write end of pipe \c
 *				(sigpipefd[1]) will be stored on success.
 *
 * \return	0 on success, -1 on error
 * \sa		man 2 pipe
 */
int open_sigpipe(int sigpipefd[2]) {
	int e;
	if (sigpipefd == NULL) {
		errno = EINVAL;
		goto EXIT1;
	};
	/* Open sigpipefd: */
	if (pipe(sigpipefd) == -1) {
		e = errno;
		warn("pipe(sigpipefd): %m\n");
		goto EXIT1;
	};
	/* Set FD_CLOEXEC and O_NONBLOCK flags: */
	for (int i = 0; i <= 1; i++) {
		if (fcntl(sigpipefd[i], F_SETFD, FD_CLOEXEC) == -1) {
			e = errno;
			warn("set FD_CLOEXEC on sigpipefd[%i]: %m\n", i);
			goto EXIT2;
		};
	};
	if (fcntl(sigpipefd[1], F_SETFL, O_NONBLOCK) == -1) {
		e = errno;
		warn("set O_NONBLOCK on sigpipefd[1]: %m\n");
		goto EXIT2;
	};
	/* Success: */
	return 0;
	/* Error: */
EXIT2:	(void) close_sigpipe(sigpipefd);
EXIT1:	errno = e;
	return -1;
};

/*!
 * \brief	Read and process incoming message from sigpipe.
 *
 * If "death" SIGCHILD is received (CLD_EXITED, CLD_KILLED or CLD_DUMPED),
 * do waitpid(), write child's pid and status into \p *wpid and \p *wstatus
 * respectively and return 1. As a side effect, this reaps zombie children.
 *
 * For non-terminal SIGCHILD messages, do nothing and return 0.
 *
 * For SIGWINCH, relay winsize change from \p origfd to \p ptsfd.
 *
 * For other signals, relay them to \p sigrelay_pid.
 *
 * \param	sigpfd		open file descriptor of signal pipe (read end)
 * \param	wpid[out]	if \p wpid is not NULL and process_sigpfd_in
 *				returns 1, \p *wpid contains pid of a child
 *				that died
 * \param	wstatus[out]	if \p wstatus is not NULL and process_sigpfd_in
 *				returns 1, \p *wstatus contains "wait status"
 *				(see man 2 waitpid) of a child that died
 * \param	origfd		original TTY fd to get winsz from
 * \param	ptsfd		slave TTY fd to copy origfd's winsz to
 * \param	sigrelay_pid	pid of a process to relay "deadly" signals to
 *
 * \return	1 if child died and its status was successfully recovered;
 *		0 if other event was successfully processed (or ignored);
 *		-1 on error (with errno of main cause of failure preserved
 *		[and optionally some warnings printed on stderr]).
 */
int process_sigpfd_in(int sigpfd, pid_t *wpid, int *wstatus,
		int origfd, int ptsfd, pid_t sigrelay_pid) {
	ssize_t ssz;
	int e, ws;
	pid_t wp;
	struct siginfo_e se;
	struct winsize winsz;

	ssz = read(sigpfd, &se, sizeof(se));
	if (ssz == -1 || ssz < 0) {
		e = errno;
		warn("read(sigpipefd): %m\n");
		goto EXIT1;
	} else if ((size_t)ssz < sizeof(se)) {
		e = EINVAL;
		warn("read(sigpipefd): incomplete read\n");
		goto EXIT1;
	};

	switch (se.se_signo) {
	case SIGCHLD:
		switch (se.se_code) {
		case CLD_EXITED:
		case CLD_KILLED:
		case CLD_DUMPED:
			wp = waitpid(se.se_pid, &ws, WNOHANG);
			if (wp == -1) {
				e = errno;
				warn("waitpid(%i,...): %m\n", se.se_pid);
				goto EXIT1;
			};
			if (wp == 0) {
				e = EINVAL;
				warn("waitpid(%i,...): not dead yet\n",
					se.se_pid);
				goto EXIT1;
			};
			if (wpid != NULL)
				*wpid = wp;
			if (wstatus != NULL)
				*wstatus = ws;
			return 1;
		};
		break;
	case SIGWINCH:
		if (ioctl(origfd, TIOCGWINSZ, &winsz) == -1) {
			e = errno;
			warn("get winsize(%i): %m\n", origfd);
			goto EXIT1;
		};
		if (ioctl(ptsfd, TIOCSWINSZ, &winsz) == -1) {
			e = errno;
			warn("set winsize(%i): %m\n", ptsfd);
			goto EXIT1;
		};
		break;
	default:
		if (kill(sigrelay_pid, se.se_signo) == -1) {
			e = errno;
			warn("kill(%i, %i): %m\n", sigrelay_pid, se.se_signo);
			goto EXIT1;
		};
		break;
	};
	return 0;
EXIT1:	errno = e;
	return -1;
};

struct xfer_buf {
	char buf[4096];
	char *s;	/* occupied part of buf */
	char *f;	/* free part of buf */
};

ssize_t read_xb(int fd, struct xfer_buf *xb) {
	if (xb == NULL) {
		errno = EINVAL;
		return -1;
	};
	if (xb->s == NULL)
		xb->s = xb->buf;
	if (xb->f == NULL)
		xb->f = xb->buf;
	char *buf_end = xb->buf + sizeof(xb->buf);
	if (xb->f >= buf_end) {
		errno = EINVAL;
		return -1;
	};
	ssize_t ssz = read(fd, xb->f, buf_end - xb->f);
	if (ssz < 0)
		warn("read(%i, ...): %m\n", fd);
	if (ssz > 0)
		xb->f += ssz;
	return ssz;
};

ssize_t write_xb(int fd, struct xfer_buf *xb) {
	if (xb == NULL || xb->s == NULL || xb->f == NULL
			/* don't permit empty writes (.s == .f): */
			|| xb->s >= xb->f
			|| xb->f > xb->buf + sizeof(xb->buf)) {
		errno = EINVAL;
		return -1;
	};
	ssize_t ssz = write(fd, xb->s, xb->f - xb->s);
	if (ssz < 0)
		warn("write(%i, ...): %m\n", fd);
	if (ssz > 0)
		xb->s += ssz;
	/* Reset .s & .f pointers to beginning when all data are written: */
	if (xb->s == xb->f) {
		xb->s = xb->buf;
		xb->f = xb->buf;
	};
	return ssz;
};

/*!
 * Transfer data between o{in/out}fd and ptmxfd until child_pid terminates.
 *
 * \param	oinfd		input descriptor of original tty (STDIN)
 * \param	ooutfd		output descriptor of original tty (STDOUT)
 * \param	ptmxfd		pty master device (open file descriptor)
 * \param	sigpfd		signal pipe descriptor (read end)
 * \param	child_ttyfd	pty slave device (open file descriptor)
 * \param	child_pid	pid of child process running on slave pty
 * \param	wstatus[out]	pointer to variable to receive child_pid's
 *				exit status
 *
 * \return	0 on success, -1 on error
 */
int pxty_main_loop(int oinfd, int ooutfd, int ptmxfd, int sigpfd,
		int child_ttyfd, int child_pid, int *wstatus) {
	/* Poll for up to 4 file descriptors simultaneously (oinfd, ooutfd,
	 * ptmxfd and sigpfd): */
	struct pollfd fds[4];
	nfds_t nfds;
	pid_t wpid;
	int wst;
	int r;
	int child_is_dead = 0;
	/* Data from oinfd to ptmxfd: */
	struct xfer_buf oi2pt = {.s = NULL, .f = NULL};
	/* Data from ptmxfd to ooutfd: */
	struct xfer_buf pt2oo = {.s = NULL, .f = NULL};
	/* Events of interest (POLLIN/POLLOUT) for oinfd, ooutfd and ptmxfd
	 * respectively: */
	short oinev, ooutev, ptev;

	/* Set O_NONBLOCK for write/output file descriptors: */
	if (fcntl(ooutfd, F_SETFL, O_NONBLOCK) == -1) {
		warn("set O_NONBLOCK on ooutfd: %m\n");
		goto EXIT1;
	};
	if (fcntl(ptmxfd, F_SETFL, O_NONBLOCK) == -1) {
		warn("set O_NONBLOCK on ptmxfd: %m\n");
		goto EXIT1;
	};

	/* Loop while child's not dead or we have pending data in transfer
	 * buffers: */
	while (!child_is_dead || oi2pt.s != oi2pt.f || pt2oo.s != pt2oo.f) {
		oinev = ooutev = ptev = 0;
		/* If oi2pt buffer is empty, wait for oinfd's POLLIN,
		 * otherwise wait for ptmxfd's POLLOUT: */
		if (oi2pt.s == oi2pt.f)
			oinev |= POLLIN;
		else
			ptev |= POLLOUT;
		/* Similarly with pt2oo buffer: */
		if (pt2oo.s == pt2oo.f)
			ptev |= POLLIN;
		else
			ooutev |= POLLOUT;
		/* fds[0] is reserved for sigpfd: */
		fds[0].fd = sigpfd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		nfds = 1;
		/* if oinev mask is non-zero, append oinfd to fds: */
		if (oinev) {
			fds[nfds].fd = oinfd;
			fds[nfds].events = oinev;
			fds[nfds].revents = 0;
			nfds++;
		};
		/* if ooutev mask is non-zero, append ooutfd to fds: */
		if (ooutev) {
			fds[nfds].fd = ooutfd;
			fds[nfds].events = ooutev;
			fds[nfds].revents = 0;
			nfds++;
		};
		/* if ptev mask is non-zero, append ptmxfd to fds: */
		if (ptev) {
			fds[nfds].fd = ptmxfd;
			fds[nfds].events = ptev;
			fds[nfds].revents = 0;
			nfds++;
		};
		do {
			r = poll(fds, nfds, 20);
		} while (r == -1 && errno == EINTR);
		if (r == -1) {
			warn("poll(): %m\n");
			goto EXIT1;
		};
		for (int i = 0; i < nfds; i++) {
			if (fds[i].fd == sigpfd && fds[i].revents & POLLIN) {
				r = process_sigpfd_in(sigpfd, &wpid, &wst,
					oinfd, child_ttyfd, child_pid);
				if (r == -1) {
					warn("process_sigpfd_in(): %m\n");
					goto EXIT1;
				} else if (r == 1 && wpid == child_pid
						&& (WIFEXITED(wst)
						|| WIFSIGNALED(wst))) {
					if (wstatus != NULL)
						*wstatus = wst;
					child_is_dead = 1;
				};
			};
			if (fds[i].fd == oinfd && fds[i].revents & POLLIN) {
				if (read_xb(oinfd, &oi2pt) < 0
						&& errno != EINTR) {
					warn("read_xb(oinfd): %m\n");
					goto EXIT1;
				};
			};
			if (fds[i].fd == ptmxfd && fds[i].revents & POLLIN) {
				if (read_xb(ptmxfd, &pt2oo) < 0
						&& errno != EINTR) {
					warn("read_xb(ptmxfd): %m\n");
					goto EXIT1;
				};
			};
			if (fds[i].fd == ooutfd && fds[i].revents & POLLOUT) {
				if (write_xb(ooutfd, &pt2oo) < 0
						&& errno != EINTR) {
					warn("write_xb(ooutfd): %m\n");
					goto EXIT1;
				};
			};
			if (fds[i].fd == ptmxfd && fds[i].revents & POLLOUT) {
				if (write_xb(ptmxfd, &oi2pt) < 0
						&& errno != EINTR) {
					warn("write_xb(ptmxfd): %m\n");
					goto EXIT1;
				};
			};
		};
	};
	return 0;

EXIT1:	kill(child_pid, SIGKILL);
	return -1;
};

int setrawmode(struct termios *t) {
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

extern char **environ;
int main(int argc, char *argv[]) {
	int ret = EXIT_FAILURE;
	int ptmxfd, ptsfd;
	char *ptsfn;
	int stdin_tty;
	struct termios tios0, tios;
	struct winsize winsz0;
	uid_t u = getuid();
	gid_t g = getgid();
	struct sigaction sa, sa0;
	pid_t pid2;

	/* Get STDIN's termios and winsize: */
	if (tcgetattr(STDIN_FILENO, &tios0) == 0) {
		stdin_tty = 1;
	} else if (errno == ENOTTY) {
		stdin_tty = 0;
		/* set "default" winsize of 80x24: */
		memset(&winsz0, 0, sizeof(winsz0));
		winsz0.ws_col = 80;
		winsz0.ws_row = 24;
	} else {
		warn("tcgetattr(%i): %m\n", STDIN_FILENO);
		goto EXIT0;
	};
	if (stdin_tty && tcgetattr(STDIN_FILENO, &tios) == -1) {
		warn("tcgetattr(%i): %m\n", STDIN_FILENO);
		goto EXIT0;
	};

	/* Open/init pty master: */
	ptmxfd = open_pty(&ptsfn, &ptsfd);
	if (ptmxfd == 1)
		goto EXIT0;

	/* Open sigpipefd: */
	if (open_sigpipe(sigpipefd) == -1)
		goto EXIT1;

	/* Set CHLD, WINCH, ALRM, TERM, INT, QUIT etc signal handler: */
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &sigpipewriter;
	for (int i = 0; i < sigc; i++) {
		if (sigaction(sigv[i], &sa, &sa0) == -1) {
			warn("sigaction SIG_%i: %m\n", sigv[i]);
			goto EXIT2;
		};
	};

	/* Set slave pty device's winsize. NOTE: do this _after_ installing
	 * sigpipewriter() handler, otherwise some SIGWINCH signals may be lost
	 * (resulting in wrong pts winsize). */
	if (ioctl(ptsfd, TIOCSWINSZ, &winsz0) == -1) {
		warn("set winsize(%i): %m\n", ptmxfd);
		goto EXIT3;
	};

	/* If STDIN is a tty, transfer its termios to slave pty device, and
	 * switch STDIN to raw mode.
	 *
	 * Otherwize calculate slave pty's new termios as "default-pts-termios
	 * + flags" (assume that OS kernel initializes new pty slaves to "sane"
	 * defaults).
	 */
	if (stdin_tty) {
		if (tcsetattr(ptsfd, TCSANOW, &tios0) == -1) {
			warn("tcsetattr(%i): %m\n", ptsfd);
			goto EXIT2;
		};
		/* Set STDIN tty to raw mode: */
		memcpy(&tios, &tios0, sizeof(tios0));
		setrawmode(&tios);
		if (tcsetattr(STDIN_FILENO, TCSANOW, &tios) == -1) {
			warn("tcsetattr(%i): %m\n", STDIN_FILENO);
			goto EXIT2;
		};
	} else {
		if (tcgetattr(ptsfd, &tios0) == -1) {
			warn("tcgetattr(%i): %m\n", ptsfd);
			goto EXIT2;
		};
		memcpy(&tios, &tios0, sizeof(tios0));
		tios.c_iflag |= IUTF8;
		if (tcsetattr(ptsfd, TCSANOW, &tios) == -1) {
			warn("tcsetattr(%i): %m\n", ptsfd);
			goto EXIT2;
		};
	};

	/* Do fork: */
	pid2 = fork();
	if (pid2 == -1) {
		warn("fork(): %m\n");
		goto EXIT3;
	};

	if (pid2 == 0) {
		/* child */
		if (close(ptmxfd) == -1)
			warn("close(ptmx): %m\n");

		restore_sigaction_dfl();
		(void) close_sigpipe(sigpipefd);

		/* Open/setup slave pty as controlling tty: */
		if (set_ctrl_tty(ptsfn, ptsfd, u, 5) == -1)
			goto CXIT;

		/* Close original ptsfd, because we have already duplicated it
		 * to STDIN/OUT/ERR: */
		if (close(ptsfd) == -1)
			warn("close(%i): %m\n", ptsfd);

		fprintf(stdout, "Hello, world!\n-- \nWBR, from %s\n", ptsfn);
		fflush(stdout);

		char *xargv[] = {"/bin/bash", NULL};
		execve(xargv[0], xargv, environ);

		/* execve() doesn't return on success: */
		warn("execve(\"%s\"): %m\n", xargv[0]);

CXIT:		free(ptsfn);
		return ret;
	} else {
		/* parent */
		int ws, ks = 0;	/* waitstatus, killsignal */

		/* Free ptsfn string early: */
		free(ptsfn);

		/* Do main loop: */
		if (pxty_main_loop(STDIN_FILENO, STDOUT_FILENO, ptmxfd,
				sigpipefd[0], ptsfd, pid2, &ws) == -1)
			goto PXIT;

		if (WIFEXITED(ws)) {
			ret = WEXITSTATUS(ws);
		} else if (WIFSIGNALED(ws)) {
			/* Store signo that killed pid2 into ks, to commit
			 * suicide later with the same signal. This serves
			 * purpose of relaying pid2's exact exit status to our
			 * parent process. */
			ks = WTERMSIG(ws);
		} else {
			/* XXX: should not reach here... */
			ks = SIGABRT;
		};

PXIT:		if (stdin_tty && tcsetattr(STDIN_FILENO, TCSANOW, &tios0) == -1)
			warn("tcsetattr(STDIN, \"restore orig.mode\"): %m\n");
		restore_sigaction_dfl();
		(void) close_sigpipe(sigpipefd);
		if (close(ptsfd) == -1)
			warn("close(%i): %m\n", ptsfd);
		if (close(ptmxfd) == -1)
			warn("close(%i): %m\n", ptmxfd);
		if (ks)
			kill(-getpid(), ks);
		return ret;
	};

EXIT3:	if (stdin_tty && tcsetattr(STDIN_FILENO, TCSANOW, &tios0) == -1)
		warn("tcsetattr(STDIN, \"restore orig.mode\"): %m\n");
EXIT2:	restore_sigaction_dfl();
	(void) close_sigpipe(sigpipefd);
EXIT1:	if (close(ptsfd) == -1)
		warn("close(%i): %m\n", ptsfd);
	free(ptsfn);
	if (close(ptmxfd) == -1)
		warn("close(%i): %m\n", ptmxfd);
EXIT0:	return ret;
};

/* vi:set sw=8 ts=8 noet tw=79: */
