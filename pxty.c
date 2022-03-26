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
				 * tcgetattr(), tcsetattr() */
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
const int sigv[] = {SIGCHLD, SIGWINCH, SIGALRM, SIGTERM, SIGINT, SIGQUIT};
const int sigc = sizeof(sigv) / sizeof(*sigv);

void sigpipewriter(int sig, siginfo_t *info, void *ucontext) {
	unsigned char b;
	switch (sig) {
	case SIGWINCH:
		b = 1;
		break;
	case SIGALRM:
		b = 2;
		break;
	case SIGTERM:
		b = 3;
		break;
	case SIGINT:
		b = 4;
		break;
	case SIGQUIT:
		b = 5;
		break;
	case SIGCHLD:
		switch (info->si_code) {
		case CLD_EXITED:
		case CLD_KILLED:
		case CLD_DUMPED:
			b = 6;
			break;
		default:
			b = 0;
			break;
		};
		break;
	};
	write(sigpipefd[1], &b, 1);
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
 * Get ISTTY flag, attrs and winsize of stdin, open pty master device, do
 * grantpt(), unlockpt() and get pty slave name.
 *
 * \param[out]	ptsfn		char pointer to receive slave pty device name
 * \param[out]	stdin_tty	stdin's ISTTY flag. Possible values: 1 (stdin
 *				is a tty), 0 (ENOTTY) or unchanged on errors
 *				other than ENOTTY
 * \param[out]	tios0		stdin's attrs (termios). Only valid if stdin is
 *				a tty.
 * \param[out]	winsz0		stdin's winsize. Only valid if stdin is	a tty.
 *
 * \return	open file descriptor of pty master device (/dev/ptmx) on
 *		success, -1 on error.
 */
int open_ptmx(char **ptsfn, int *stdin_tty,
		struct termios *tios0, struct winsize *winsz0) {
	int ptmxfd;
	char *p;
	if (ptsfn == NULL || stdin_tty == NULL
			|| tios0 == NULL || winsz0 == NULL)
		goto EXIT1;

	/* Get original tty settings of stdin: */
	if (tcgetattr(STDIN_FILENO, tios0) == 0) {
		*stdin_tty = 1;
	} else if (errno == ENOTTY) {
		*stdin_tty = 0;
	} else {
		warn("tcgetattr(stdin): %m\n");
		goto EXIT1;
	};
	/* Get stdin's WINSZ, if *stdin_tty: */
	if (*stdin_tty && ioctl(STDIN_FILENO, TIOCGWINSZ, winsz0) == -1) {
		warn("get WINSZ (stdin): %m\n");
		goto EXIT1;
	};

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

int open_pts(char *ptsfn, uid_t u, gid_t g) {
	int ptsfd;
	int ret = -1;

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

void close_sigpipefd(int sigpipefd[2]) {
	for (int i = 1; i >= 0; i--) {
		if (close(sigpipefd[i]) == -1)
			warn("close(sigpipefd[%i]): %m\n", i);
	};
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

	/* Open/init pty master: */
	ptmxfd = open_ptmx(&ptsfn, &stdin_tty, &tios0, &winsz0);
	if (ptmxfd == 1)
		goto EXIT0;
	fprintf(stderr, "pts: %s\n", ptsfn);

	/* Open sigpipefd: */
	if (pipe(sigpipefd) == -1) {
		warn("pipe(sigpipefd): %m\n");
		goto EXIT2;
	};
	for (int i = 0; i <= 1; i++) {
		if (fcntl(sigpipefd[i], F_SETFD, FD_CLOEXEC) == -1) {
			warn("set FD_CLOEXEC on sigpipefd[%i]: %m\n", i);
			goto EXIT3;
		};
	};
	if (fcntl(sigpipefd[1], F_SETFL, O_NONBLOCK) == -1) {
		warn("set O_NONBLOCK on sigpipefd[1]: %m\n");
		goto EXIT3;
	};

	/* Set CHLD, WINCH, ALRM, TERM, INT, QUIT signal handler: */
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &sigpipewriter;
	for (int i = 0; i < sigc; i++) {
		if (sigaction(sigv[i], &sa, &sa0) == -1) {
			warn("sigaction SIG_%i: %m\n", sigv[i]);
			goto EXIT3;
		};
	};

	pid2 = fork();
	if (pid2 == -1) {
		warn("fork(): %m\n");
		goto EXIT3;
	} else if (pid2 == 0) {
		/* child */
		if (close(ptmxfd) == -1)
			warn("close(ptmx): %m\n");

		restore_sigaction_dfl();
		close_sigpipefd(sigpipefd);

		/* Open/chown/set_std slave pty: */
		if (open_pts(ptsfn, u, 5) == -1)
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
		goto EXIT1;
	};

EXIT4:	restore_sigaction_dfl();
EXIT3:	close_sigpipefd(sigpipefd);
EXIT2:	free(ptsfn);
EXIT1:	if (close(ptmxfd) == -1)
		warn("close(ptmx): %m\n");
EXIT0:	return ret;
};

/* vi:set sw=8 ts=8 noet tw=79: */
