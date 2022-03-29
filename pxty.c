/*!
 * Prototype code for pty proxy (a la `su -P`), to be incorporated into nsrun
 * later.
 *
 * \version	1.0
 * \author	xrgtn
 * \date	2022
 */

#define _XOPEN_SOURCE	500	/* CLD_EXITED/KILLED/DUMPED, uid_t, gid_t */
#define _POSIX_C_SOURCE	199309L	/* sigaction(), siginfo_t */
#include <stddef.h>		/* NULL, EXIT_SUCCESS, EXIT_FAILURE */
#include <unistd.h>		/* fork(), STDIN/OUT/ERR_FILENO, close(),
				 * write(), uid_t, gid_t, pid_t */
#include <stdlib.h>		/* free() */
#include <fcntl.h>		/* O_RDWR, O_NOCTTY, fcntl(), F_SETFD,
				 * FD_CLOEXEC, F_SETFL, O_NONBLOCK */
#include <stdio.h>		/* fprintf(), stderr */
#include <errno.h>		/* errno, ENOTTY, EINTR */
#include <string.h>		/* memcpy(), memset() */
#include <termios.h>		/* struct termios, struct winsize,
				 * tcgetattr(), tcsetattr(), TCSANOW */
#include <sys/wait.h>		/* waitpid(), WNOHANG, WIFEXITED(),
				 * WEXITSTATUS(), WIFSIGNALED(), WTERMSIG() */
#include <sys/ioctl.h>		/* ioctl(), TIOCGWINSZ, TIOCSWINSZ */
#include <poll.h>		/* poll(), struct pollfd, nfds_t, POLLIN,
				 * POLLOUT */
#include <signal.h>		/* sigaction(), siginfo_t, SIGCHLD, SIGWINCH,
				 * SIGALRM, SIGTERM, SIGINT, SIGQUIT,
				 * struct sigaction, SA_SIGINFO,
				 * CLD_EXITED/KILLED/DUMPED */
#include "pty.h"		/* open_pty(), set_ctrl_tty() */

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
