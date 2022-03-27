/*!
 * Temporary prototype code for pty proxy (a la `su -P`).
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
#include <sys/wait.h>		/* wait(), WIFEXITED(), WEXITSTATUS(),
				 * WIFSIGNALED(), WTERMSIG() */
#include <fcntl.h>		/* fcntl(), F_SETFL, O_NONBLOCK */
#include <sys/ioctl.h>		/* ioctl(), TIOCGWINSZ, TIOCSWINSZ */
#include <poll.h>		/* poll(), struct pollfd, POLLIN, POLLOUT */
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
	unsigned char b;
	struct siginfo_e se;
	ssize_t ssz;
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
};

int waitall(pid_t child_pid) {
	int ret = EXIT_FAILURE;
	int wst, r, f = 0;
	pid_t wpid;
	do {
		wpid = wait(&wst);
		if (wpid == child_pid) {
			r = wst;
			f = 1;
		};
	} while (!(wpid == -1 && errno != EINTR));
	if (wpid == -1 && errno != ECHILD) {
		/* ECHILD: The calling process has no existing
		 * unwaited-for child processes.
		 * I.e. all children have already terminated. */
		warn("wait(): %m\n");
		ret = EXIT_FAILURE;
	} else if (!f) {
		ret = EXIT_FAILURE;
	} else if (WIFEXITED(r)) {
		ret = WEXITSTATUS(r);
	} else if (WIFSIGNALED(r)) {
		ret = EXIT_FAILURE;
		/* Commit suicide with the same signal, to relay
		 * exec_pid's exact wstatus to our parent: */
		kill(getpid(), WTERMSIG(r));
	};
	return ret;
};

/*!
 * \bief	Open and setup pseudo-terminal master device.
 *
 * Open pty master device, do grantpt(), unlockpt() and get slave
 * pseudo-terminal device name.
 *
 * \param[out]	ptsfn		char pointer to receive slave pty device name
 *
 * \return	open file descriptor of pty master device (/dev/ptmx) on
 *		success, -1 on error.
 */
int open_ptmx(char **ptsfn) {
	int ptmxfd;
	char *p;
	if (ptsfn == NULL)
		goto EXIT1;

	/* Open /dev/ptmx The-POSIX-Way: */
	ptmxfd = posix_openpt(O_RDWR | O_NOCTTY);
	if (ptmxfd == -1) {
		warn("posix_openpt(O_RDWR | O_NOCTTY): %m\n");
		goto EXIT1;
	};
	if (grantpt(ptmxfd) == -1) {
		warn("grantpt(ptmx): %m\n");
		goto EXIT2;
	};
	if (unlockpt(ptmxfd) == -1) {
		warn("unlockpt(ptmx): %m\n");
		goto EXIT2;
	};
	p = ptsname(ptmxfd);
	if (p == NULL) {
		warn("ptsname(ptmx): %m\n");
		goto EXIT2;
	};
	*ptsfn = strdup(p);
	if (*ptsfn == NULL) {
		warn("strdup(\"%s\"): %m\n", p);
		goto EXIT2;
	};
	return ptmxfd;
EXIT2:	if (close(ptmxfd) == -1)
		warn("close(ptmx): %m\n");
EXIT1:	return -1;
};

/*!
 * \brief	Open and setup controlling tty.
 *
 * Open specified tty device file \p ptsfn, change its owner to \p u:g and mode
 * to 0600, initialize attrs/winsize if \p tios/winsz is not NULL, start new
 * terminal session, set \p ptsfn as controlling terminal and reopen
 * stdin/out/err to it.
 *
 * \param	ptsfn	tty defice filename
 * \param	u	uid to set as tty owner user
 * \param	g	gid to set as tty owner group
 * \param	tios	attrs to initialize tty (if not NULL)
 * \param	winsz	winsize to initialize tty (if not NULL)
 *
 * \return	0 on success, -1 on error.
 */
int open_pts(char *ptsfn, uid_t u, gid_t g,
		const struct termios *tios, const struct winsize *winsz) {
	int ptsfd;
	int ret = -1;

	if (ptsfn == NULL)
		goto EXIT0;

	ptsfd = open(ptsfn, O_RDWR | O_NOCTTY);
	if (ptsfd == -1) {
		warn("open(\"%s\", O_RDWR | O_NOCTTY): %m\n", ptsfn);
		goto EXIT0;
	};
	if (fchown(ptsfd, u, g) == -1) {
		warn("fchown(\"%s\", %u, %u): %m\n", ptsfn,
			(unsigned)u, (unsigned)g);
		goto EXIT1;
	};
	if (fchmod(ptsfd, 0600) == -1) {
		warn("fchmod(\"%s\", 0600): %m\n", ptsfn);
		goto EXIT1;
	};
	if (tios != NULL && tcsetattr(ptsfd, TCSANOW, tios) == -1) {
		warn("tcsetattr(\"%s\", ...): %m\n", ptsfn);
		goto EXIT1;
	};
	if (winsz != NULL && ioctl(ptsfd, TIOCSWINSZ, winsz) == -1) {
		warn("set WINSZ (\"%s\"): %m\n", ptsfn);
		goto EXIT1;
	};
	if (setsid() == (pid_t)-1) {
		warn("setsid(): %m\n");
		goto EXIT1;
	};
	if (ioctl(ptsfd, TIOCSCTTY, 0) == -1) {
		warn("ioctl(\"%s\", TIOCSCTTY, 0): %m\n", ptsfn);
		goto EXIT1;
	};
	if (ptsfd != STDIN_FILENO
			&& dup2(ptsfd, STDIN_FILENO) == -1) {
		warn("dup2(\"%s\", %i): %m\n", ptsfn, STDIN_FILENO);
		goto EXIT1;
	};
	if (ptsfd != STDOUT_FILENO
			&& dup2(ptsfd, STDOUT_FILENO) == -1) {
		warn("dup2(\"%s\", %i): %m\n", ptsfn, STDOUT_FILENO);
		goto EXIT1;
	};
	if (ptsfd != STDERR_FILENO
			&& dup2(ptsfd, STDERR_FILENO) == -1) {
		warn("dup2(\"%s\", %i): %m\n", ptsfn, STDERR_FILENO);
		goto EXIT1;
	};
	ret = 0;
EXIT1:	if (close(ptsfd) == -1)
		warn("close(\"%s\"): %m\n", ptsfn);
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
 * Get tty attrs and winsize of \p fd.
 *
 * \param[in]	fd	file descriptor
 * \param[out]	tios	fd tty attrs (termios).
 * \param[out]	winsz	fd tty winsize.
 *
 * \return	1 on success, 0 if fd is not a tty, -1 on error.
 */
int get_tty_params(int fd, struct termios *tios, struct winsize *winsz) {
	/* Get current tty attrs of fd: */
	if (tios == NULL) {
		errno = EINVAL;
		return -1;
	};
	if (tcgetattr(fd, tios) == -1) {
		if (errno == ENOTTY) {
			return 0;
		} else {
			warn("tcgetattr(%i): %m\n", fd);
			return -1;
		};
	};
	/* Get current winsize of fd: */
	if (winsz == NULL) {
		errno = EINVAL;
		return -1;
	};
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, winsz) == -1) {
		warn("get winsize(%i): %m\n", fd);
		return -1;
	};
	return 1;
};

int main(int argc, char *argv[]) {
	int ret = EXIT_FAILURE;
	int ptmxfd;
	char *ptsfn;
	int stdin_tty;
	struct termios tios0;
	struct winsize winsz0;
	uid_t u = getuid();
	gid_t g = getgid();
	struct sigaction sa, sa0;
	pid_t pid2;

	/* Get STDIN's tty params: */
	stdin_tty = get_tty_params(STDIN_FILENO, &tios0, &winsz0);
	if (stdin_tty == -1)
		goto EXIT0;

	/* Open/init pty master: */
	ptmxfd = open_ptmx(&ptsfn);
	if (ptmxfd == 1)
		goto EXIT0;
	fprintf(stderr, "pts: %s\n", ptsfn);

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

	/* Do fork: */
	pid2 = fork();
	if (pid2 == -1) {
		warn("fork(): %m\n");
		goto EXIT2;
	};

	if (pid2 == 0) {
		/* child */
		if (close(ptmxfd) == -1)
			warn("close(ptmx): %m\n");

		restore_sigaction_dfl();
		(void) close_sigpipe(sigpipefd);

		/* Open/chown/setup slave pty: */
		if (open_pts(ptsfn, u, 5, stdin_tty ? &tios0 : NULL,
				stdin_tty ? &winsz0 : NULL) == -1)
			goto CXIT1;

		fprintf(stdout, "Hello, world!\n");
		fflush(stdout);

		ret = EXIT_SUCCESS;
CXIT1:		free(ptsfn);
		return ret;
	} else {
		/* parent */
		free(ptsfn);
		ret = waitall(pid2);
		restore_sigaction_dfl();
		(void) close_sigpipe(sigpipefd);
		if (close(ptmxfd) == -1)
			warn("close(ptmx): %m\n");
		return ret;
	};

EXIT2:	restore_sigaction_dfl();
	(void) close_sigpipe(sigpipefd);
EXIT1:	free(ptsfn);
	if (close(ptmxfd) == -1)
		warn("close(ptmx): %m\n");
EXIT0:	return ret;
};

/* vi:set sw=8 ts=8 noet tw=79: */