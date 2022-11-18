#define _GNU_SOURCE	/* asprintf(), vasprintf(), setns(), unshare(), %m? */
#include <stddef.h>	/* NULL, EXIT_SUCCESS, EXIT_FAILURE */
#include <termios.h>	/* tcgetattr(), tcsetattr() */
#include <unistd.h>	/* tcgetattr(), tcsetattr(), execve(), pipe(), read(),
			 * write(), close(), fork(), chdir(), chroot(),
			 * getgroups(), sethostname(), STDIN_FILENO */
#include <stdlib.h>	/* getenv(), setenv(), malloc(), free() */
#include <stdio.h>	/* printf(), fprintf(), asprintf(), vasprintf(),
			 * stderr, stdout */
#include <stdarg.h>	/* va_list, va_start(), va_end() */
#include <errno.h>	/* errno, ENOTTY */
#include <sys/mount.h>	/* mount(), umount2(), MS_REC, MS_SLAVE, MS_PRIVATE,
			 * MNT_DETACH, MS_NODEV, MS_NOEXEC, MS_NOSUID */
#include <sys/wait.h>	/* wait(), waitpid(), WIFxxxx() */
#include <fcntl.h>	/* open(), O_RDONLY, O_WRONLY, O_CREAT, O_TRUNC */
#include <sched.h>	/* setns(), CLONE_NEWxxx, unshare() */
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME	0x00000080
#endif
#include <grp.h>	/* setgroups() */
#include <string.h>	/* strlen() */
#include <sys/capability.h>	/* cap_t, cap_get_proc(), cap_to_text(),
				 * cap_free(), XXX */
#include <signal.h>	/* kill(), SIGKILL */
#include <sys/syscall.h>	/* syscall(), SYS_pidfd_open, SYS_pivot_root */
#include "getoptv.h"	/* struct opt, getoptv() */
#include "uid_pw.h"	/* struct ugids, getugids(), setugids(), ugids_eq(),
			 * struct passwb, getpwb() */

extern char **environ;	/* man 3p environ, man 7 environ, man 3p exec. */

/* This program's name, defaulting to basename of C source file. To be set to
 * "actual" program name as indicated by argv[0]. */
static char *progname = __BASE_FILE__;

#define err(...) do { \
	fprintf(stderr, "ERROR: " __VA_ARGS__); \
	fflush(stderr); \
	} while (0)
#define warn(...) do { \
	fprintf(stderr, "WARNING: " __VA_ARGS__); \
	fflush(stderr); \
	} while (0)
#define info(fmt, ...) do { \
	fprintf(stdout, "%s: " fmt, progname __VA_OPT__(,) __VA_ARGS__); \
	fflush(stdout); \
	} while (0)
#define info2(fmt, ...) do { \
	fprintf(stdout, fmt __VA_OPT__(,) __VA_ARGS__); \
	fflush(stdout); \
	} while (0)

#ifdef DEBUG
#define debug(fmt, ...) do { \
	fprintf(stderr, "%s[%i,%s]: " fmt, __BASE_FILE__, __LINE__, \
	__FUNCTION__ __VA_OPT__(,) __VA_ARGS__); \
	fflush(stderr); \
	} while (0)
#else
#define debug(fmt, ...)
#endif

/* Compare two strings and return 1 if they are equal, 0 otherwise (cf Perl's
 * "eq" operator). */
static inline int str_eq(const register char *a, const register char *b) {
	if (a == NULL) {
		return b == NULL ? 1 : 0;
	} else {
		if (b == NULL) return 0;
		while (*a == *b && *a != '\0' && *b != '\0') a++, b++;
		return *a == '\0' && *b == '\0' ? 1 : 0;
	};
};

struct src_tgt {
	char *src;
	char *tgt;
};

/**
 * Record src=>tgt binding request to *@mnt struct, if @t option has been
 * encountered twice - one time without parameter and one time with it (in any
 * order).
 * E.g.:
 *   -n=/run/netns/ns0 -n
 *   -nn=/run/netns/ns0
 *   -n -n=/run/netns/ns0
 *
 * @param	@mnt	pointer to src_tgt struct;
 * @param	@t	pointer to opt decriptor, filled in by call to
 *			@getoptv(). @t->val/vals[] must contain mount target
 *			path;
 * @param	@srcfmt	format string for vasprintf() to generate pathname of
 *			the source ns object to be mounted (typically using pid
 *			as a parameter), e.g. "/proc/12345/ns/cgroup"
 *
 * @return	1 on success, 0 on error.
 */
static int req_src_tgt(struct src_tgt *mnt, const struct opt *t,
		const char *srcfmt, ...) {
	char *src = NULL, *tgt = NULL;
	int ret_int;
	va_list ap;

	/* Find mount destination from t. It must have .cnt > .vcnt and at
	 * least one non-NULL value: */
	if (t->cnt > t->vcnt) tgt = t->val;

	/* If no target [path]name is found in @t opt, return 0: */
	if (tgt == NULL) return 0;

	/* Generate source [path]name: */
	va_start(ap, srcfmt);
	ret_int = vasprintf(&src, srcfmt, ap);
	va_end(ap);
	if (ret_int < 1) {
		warn("vasprintf(%s, ...): %m\n", srcfmt);
		return 0;
	};
	mnt->src = src;
	mnt->tgt = tgt;
	debug("schedule mount --bind %s %s\n", src, tgt);
	return 1;
};

/* Do chdir(dir) and chroot(dir). Return 1 on success, 0 on failure (and print
 * warnings to stderr). */
static int chrootdir(const char *dir) {
	if (dir == NULL)
		return 0;
	if (chdir(dir) != 0) {
		warn("chdir(%s): %m\n", dir);
		return 0;
	};
	if (chroot(".") != 0) {
		warn("chroot(%s): %m\n", dir);
		return 0;
	};
	return 1;
};

/* Do chdir() and pivot_root() to dir and unmount old_root. Bind-mount dir to
 * itself to make it a mount if it's not already a mount. Return true on
 * success, false on failure (and print warnings to stderr). */
static int pivotrootdir(const char *dir) {
	int mkprivate_einval = 0;
	const char *oldroot = "."; /*"oldroot"*/
	if (dir == NULL)
		return 0;
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
		warn("mount --make-rprivate /: %m\n");
		if (mount(NULL, "/", NULL, MS_PRIVATE, NULL) != 0)
			warn("mount --make-private /: %m\n");
	} else {
		debug("mount --make-rprivate /: OK\n");
	};
	if (mount(NULL, dir, NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
		if (errno == EINVAL)
			mkprivate_einval++;
		else
			warn("mount --make-rprivate %s: %m\n", dir);
		if (mount(NULL, dir, NULL, MS_PRIVATE, NULL) != 0) {
			if (errno == EINVAL)
				mkprivate_einval++;
			if (mkprivate_einval != 2)
				warn("mount --make-private %s: %m\n", dir);
		} else {
			debug("mount --make-private %s: OK\n", dir);
		};
	} else {
		debug("mount --make-rprivate %s: OK\n", dir);
	};
	if (mkprivate_einval == 2) {
		if (mount(dir, dir, NULL, MS_REC | MS_BIND, NULL) != 0)
			warn("mount --rbind %s %s: %m\n", dir, dir);
		else
			debug("mount --rbind %s %s: OK\n", dir, dir);
	};
	if (chdir(dir) != 0) {
		warn("chdir(%s): %m\n", dir);
		return 0;
	} else {
		debug("chdir(%s): OK\n", dir);
	};
	if (syscall(SYS_pivot_root, ".", oldroot) != 0) {
		warn("pivot_root(%s, %s/%s): %m\n", dir, dir, oldroot);
		return 0;
	};
	if (umount2(oldroot, MNT_DETACH) != 0) {
		warn("umount2(%s/%s, MNT_DETACH): %m\n", dir, oldroot);
		return 0;
	};
	if (chdir("/") != 0) {
		warn("chdir(/): %m\n");
		return 0;
	};
	return 1;
};

/* @return	1 on success (sz bytes of buf written to fd), 0 otherwise. */
static int writeall(int fd, const char *buf, size_t sz, const char *fn) {
	size_t written = 0;
	if (buf == NULL) return 0;
	ssize_t ssz;
	while (written < sz) {
		ssz = write(fd, buf + written, sz - written);
		if (ssz <= 0) {
			if (errno == EINTR)
				continue;
			warn("write(%s): %m\n", fn);
			return 0;
		} else {
			written += ssz;
		};
	};
	return 1;
};

/* @return	1 on success (whole str to fn), 0 otherwise. */
static int writestr1(const char *fn, const char *str) {
	int fd, ret;
	if (fn == NULL || str == NULL) return 0;
	if ((fd = open(fn, O_WRONLY)) == -1) {
		warn("open(%s, O_WRONLY): %m\n", fn);
		return 0;
	};
	ret = writeall(fd, str, strlen(str), fn);
	close(fd);
	return ret;
};

/* Open specified file (typically either "/proc/self/uid_map" or
 * "/proc/self/gid_map") and write mapping for the single specified
 * uid/gid. If uid/gid is not 0, also add 0 -> 0 mapping.
 *
 * @param	fn	filename of uid/gid map
 * @param	from	uid/gid in inner namespace
 * @param	to	uid/gid in outer namespace
 *
 * @return	1 on success (map written to fn), 0 otherwise. */
static int map_cred(const char *fn, int from, int to) {
	int fd = -1;
	char *buf = NULL;
	int ret = 0;
	fd = open(fn, O_WRONLY);
	if (fd == -1) {
		warn("open(%s, O_WRONLY): %m\n", fn);
		goto EXIT0;
	};
	if (asprintf(&buf, "%u %u 1\n%s", from, to,
			from && to ? "0 0 1\n" : "") <= 0) {
		warn("asprintf(): %m\n");
		goto EXIT0;
	};
	if (writeall(fd, buf, strlen(buf), fn)) ret = 1;
EXIT0:	if (buf != NULL) free(buf);
	if (fd >= 0) close(fd);
	return ret;
};

/* Reads sz bytes from file descriptor fd into buf.
 *
 * @return	1 on success, 0 on failure. */
static int readall(int fd, char *buf, size_t sz, const char *fdesc) {
	size_t numread = 0;
	ssize_t ssz;
	if (buf == NULL) return 0;
	while (numread < sz) {
		ssz = read(fd, buf + numread, sz - numread);
		if (ssz > 0) {
			numread += ssz;
		} else if (errno == EINTR) {
			continue;
		} else {
			warn("read %s: %m\n", fdesc);
			return 0;
		};
	};
	return 1;
};

static int print_caps(void) {
	cap_t caps;
	char *captxt;
	int ret = 0;
	if ((caps = cap_get_proc()) == NULL) {
		warn("cap_get_proc(): %m\n");
	} else {
		if ((captxt = cap_to_text(caps, NULL)) == NULL) {
			warn("cap_to_text(): %m\n");
		} else {
			debug("%s\n", captxt);
			cap_free(captxt);
			ret = 1;
		};
		cap_free(caps);
	};
	return ret;
};

int oldns_main(int rfd, int wfd, int mntc, struct src_tgt *mnt) {
	char ping;
	int i, ret = EXIT_SUCCESS;
	char *s;
	pid_t p;

	/* Wait for ping from parent: */
	while (1) {
		if (!readall(rfd, &ping, 1, "pipe to oldns"))
			goto EXIT1;
		debug("oldns received '%.1s' cmd\n", &ping);
		switch (ping) {
		case 'm':
			/* Do bind mounts: */
			ret = EXIT_SUCCESS;
			for (i = 0; i < mntc; i++) {
				if (0 != mount(mnt[i].src, mnt[i].tgt,
						NULL, MS_BIND, NULL)) {
					ret = EXIT_FAILURE;
					warn("mount --bind %s %s: %m\n",
						mnt[i].src, mnt[i].tgt);
				};
			};
			break;
		case 'w':
			/* Write /proc/$PID/uid_map, setgroups, and
			 * gid_map */
			ret = EXIT_SUCCESS;
			if (!readall(rfd, (char *)&p, sizeof(p),
					"pipe to oldns"))
				goto EXIT1;
			if (asprintf(&s, "/proc/%u/uid_map", p) == -1)
				goto EXIT1;
			if (!writestr1(s, "0 0 65534\n"))
				ret = EXIT_FAILURE;
			free(s);
			if (asprintf(&s, "/proc/%u/setgroups", p)
					== -1)
				goto EXIT1;
			if (!writestr1(s, "allow"))
				ret = EXIT_FAILURE;
			free(s);
			if (asprintf(&s, "/proc/%u/gid_map", p) == -1)
				goto EXIT1;
			if (!writestr1(s, "0 0 65534\n"))
				ret = EXIT_FAILURE;
			free(s);
			break;
		case 'q':
			/* Quit: */
			goto EXIT0;
		default:
			err("invalid oldns cmd '%.1s'\n", &ping);
			goto EXIT1;
		};
		/* Send cmd result to parent: */
		if (!writeall(wfd, (char *)&ret, sizeof(ret),
				"pipe from oldns"))
			goto EXIT1;
	};

EXIT0:	while (mntc > 0) {
		if (mnt[--mntc].src != NULL)
			free(mnt[mntc].src);
	};
	return ret;

EXIT1:	ret = EXIT_FAILURE;
	goto EXIT0;
}

/* Cmdline options: */
enum optkeys {opt_e, opt_h, opt_l, opt_r, opt_P,
	opt_i, opt_m, opt_n, opt_p, opt_u, opt_C, opt_T, opt_U,
	opt_t, opt_inv};

struct namespace {
	int	type;
	char	*fmt;
	int	fd;
	const char *fn;
};

int runner_main(char **argv, struct opt *o, struct namespace *nsp,
		int unshared, struct ugids cr) {
	int ret = EXIT_FAILURE;
	int chrooted = 0;
	int i;
	char *newhostname = "localhost";
	pid_t exec_pid = 1, wpid;
	int wstatus = 0;
	/* envp/argv to run: */
	char *runprog = NULL;		/* executable [path]name */
	char *shell = "/bin/sh";	/* default shell */
	char *defargv[2] = {shell, NULL};
	char **runargv = defargv;
	char *logname = NULL, *term = NULL;
	char *defpath[] = {"/sbin:/bin:/usr/sbin:/usr/bin", "/bin:/usr/bin"};
	char *path = defpath[1];
	char *home = NULL;
	struct passwb *pw = NULL;

	print_caps();

	/* Do chroot()/pivot_root() after creating/entering new namespaces
	 * and mapping uid/gid: */
	if (o[opt_r].val != NULL) {
		if (unshared & CLONE_NEWNS) {
			if (pivotrootdir(o[opt_r].val)) {
				info("pivoted root to %s\n", o[opt_r].val);
				chrooted++;
			} else if (chrootdir(o[opt_r].val)) {
				info("changed root to %s\n", o[opt_r].val);
				chrooted++;
			} else {
				goto EXIT1;
			};
		} else {
			if (chrootdir(o[opt_r].val)) {
				info("changed root to %s\n", o[opt_r].val);
				chrooted++;
			} else {
				goto EXIT1;
			};
		};
	};

	/* Mounr procfs on /proc if in chroot or in new mount namespace.
	 * Ditto with devpts, shmem and mqueue: */
	if (chrooted || unshared & CLONE_NEWNS) {
		int fd = -1;
		int proc = 0, pci = 0, pdev = 0,
			mq = 0, pts = 0, shm = 0, run = 0, m = 0;
		/* Mount /proc and empty /proc/bus/pci/devices: */
		if (mount("proc", "/proc", "proc",
				MS_NODEV | MS_NOEXEC | MS_NOSUID,
				NULL) == 0)
			proc = 1;
		else
			warn("mount -t proc proc /proc: %m\n");
		if (proc) {
			if (mount("x", "/proc/bus/pci", "tmpfs",
					MS_NODEV | MS_NOEXEC | MS_NOSUID,
					"nr_blocks=128,nr_inodes=32") == 0)
				pci = 1;
			else
				warn("mount -t tmpfs x /proc/bus/pci: %m\n");
		};
		if (pci) {
			if ((fd = open("/proc/bus/pci/devices",
					O_WRONLY | O_CREAT | O_TRUNC, 0644))
					!= -1) {
				pdev = 1;
				close(fd);
			} else {
				warn("creat(/proc/bus/pci/devices): %m\n");
			};
		};

		/* Mount /dev subsystems: */
		if (unshared & CLONE_NEWIPC) {
			if (mount("mq", "/dev/mqueue", "mqueue", MS_NODEV |
					MS_NOEXEC | MS_NOSUID, NULL) == 0)
				mq = 1;
			else
				warn("mount -t mqueue mq /dev/mqueue: %m\n");
		};
		if (mount("pts", "/dev/pts", "devpts",
				MS_NOEXEC | MS_NOSUID, NULL) == 0)
			pts = 1;
		else
			warn("mount -t devpts pts /dev/pts: %m\n");
		if (mount("shm", "/dev/shm", "tmpfs", MS_NODEV |
				MS_NOEXEC | MS_NOSUID, NULL) == 0)
			shm = 1;
		else
			warn("mount -t tmpfs shm /dev/shm: %m\n");
		if (mount("run", "/run", "tmpfs", MS_NODEV |
				MS_NOEXEC | MS_NOSUID,
				"nr_inodes=2048,nr_blocks=8192") == 0)
			run = 1;
		else
			warn("mount -t tmpfs run /run: %m\n");

		/* Report what has been mounted: */
		if (proc | pci | pdev | mq | pts | shm | run) {
			info("mounted");
			if (proc) info2("%s /proc", m++ ? "," : "");
			if (pci)  info2("%s /proc/bus/pci", m++ ? "," : "");
			if (pdev) info2("%s /proc/bus/pci/devices",
				m++ ? "," : "");
			if (mq)   info2("%s /dev/mqueue", m++ ? "," : "");
			if (pts)  info2("%s /dev/pts", m++ ? "," : "");
			if (shm)  info2("%s /dev/shm", m++ ? "," : "");
			if (run)  info2("%s /run", m++ ? "," : "");
			info2("\n");
		};
	};

	/* Reset hostname if unshared CLONE_NEWUTS */
	if (unshared & CLONE_NEWUTS) {
		if (sethostname(newhostname, strlen(newhostname)) == 0)
			info("set hostname to \"%s\"\n", newhostname);
		else
			warn("set hostname to \"%s\": %m\n", newhostname);
	};

	exec_pid = fork();
	if (exec_pid == -1) {
		err("fork(exec): %m\n");
		goto EXIT1;
	} else if (exec_pid != 0) {
		/* Here we do duties of /sbin/init, namely reaping zombie
		 * processes while waiting for exec_pid to finish. */
		int r, f = 0;
		do {
			wpid = wait(&wstatus);
			if (wpid == exec_pid) {
				r = wstatus;
				f = 1;
			};
		} while (!(wpid == -1 && errno != EINTR));
		if (wpid == -1 && errno != ECHILD) {
			/* ECHILD: The calling process has no existing
			 * unwaited-for child processes.
			 * I.e. all children have already terminated. */
			err("wait(): %m\n");
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
		goto EXIT0;
	};

	/* From here on it's exec_pid running: */

	/* Get user's shell & co if there's nothing left on cmdline: */
	pw = getpwb(cr.euid);
	if (pw == NULL || pw->pwd.pw_shell == NULL
			|| pw->pwd.pw_shell[0] == '\0') {
		warn("no shell for uid %u, fallback to %s\n", cr.euid, shell);
	} else {
		shell = pw->pwd.pw_shell;
	};

	/* Calculate values for user's new env: */
	term = getenv("TERM");
	path = defpath[cr.euid == 0 ? 0 : 1];
	logname = (pw != NULL && pw->pwd.pw_name != NULL
		&& pw->pwd.pw_name[0] != '\0') ? pw->pwd.pw_name
		: (cr.euid == 0) ? "root" : "nobody";
	home = (pw != NULL && pw->pwd.pw_dir != NULL
		&& pw->pwd.pw_dir[0] != '\0') ? pw->pwd.pw_dir
		: (cr.euid == 0) ? "/root" : "/var/empty";
	/* Reset user's env: */
	environ = NULL;
	if (setenv("PATH", path, 1) != 0)
		warn("setenv(PATH=%s), %m\n", path);
	if (setenv("SHELL", shell, 1) != 0)
		warn("setenv(SHELL=%s), %m\n", shell);
	if (setenv("USER", logname, 1) != 0)
		warn("setenv(USER=%s), %m\n", logname);
	if (setenv("LOGNAME", logname, 1) != 0)
		warn("setenv(LOGNAME=%s), %m\n", logname);
	if (setenv("HOME", home, 1) != 0)
		warn("setenv(HOME=%s), %m\n", home);
	if (term != NULL) {
		if (setenv("TERM", term, 1) != 0)
			warn("setenv(TERM=%s), %m\n", term);
	};
	if (o[opt_P].cnt > 0) {
		for (i = 0; i < o[opt_P].cnt; i++) {
			if (o[opt_P].vals[i] != NULL) {
				if (putenv(o[opt_P].vals[i]) != 0)
					warn("putenv(%s), %m\n",
						o[opt_P].vals[i]);
			};
		};
	};

	/* Run specified command (or shell): */
	if (argv[0] != NULL) {
		runargv = argv;
	} else {
		defargv[0] = shell;
		defargv[1] = NULL;
		runargv = defargv;
	};
	/* Prepend '-' character in-place if necesary: */
	runprog = runargv[0];
	if (o[opt_l].cnt) {
		if (asprintf(runargv, "-%s", runprog) <= 0)
			runargv[0] = runprog;
	};
	info("executing %s\n", runargv[0]);
	execve(runprog, runargv, environ);
	/* Successful exec() doesn't return, so... */
	err("execve(%s): %m\n", runargv[0]);
	goto EXIT1;

EXIT0:	if (pw != NULL) free(pw);
	for (i = opt_i; i <= opt_U; i++) {
		if (nsp[i].fd != -1)
			close(nsp[i].fd);
	};
	if (exec_pid != -1 && exec_pid != 0)
		kill(exec_pid, SIGKILL);
	freeoptv(o);
	return ret;

EXIT1:	ret = EXIT_FAILURE;
	goto EXIT0;
}

/* man 3p exec:
 *
 * Since this volume of POSIX.1‐2017 defines the global variable environ, which
 * is also provided by historical implementations and can be used anywhere that
 * envp could be used, there is no functional need for the envp argument.
 *
 * Well, it's certainly strange to refer to POSIX in a code full of GNU
 * extensions and strictly Linux-specific features (like setns()/unshare() and
 * syscall(SYS_pidfd_open, ...))
 */
int main(int argc, char *argv[]) {
	int ret = EXIT_FAILURE, i;
	char *chp;
	/* Creds: */
	struct ugids cr1, cr2;
	int ngroups = 0;
	/* TTY params: */
	struct termios ttios;
	/* Cmdline options and results of optparsing: : */
	struct opt o[] = {
		[opt_e] = {'e', REQUIRED_VAL},
		[opt_h] = {'h', NO_VAL},
		[opt_l] = {'l', NO_VAL},
		[opt_r] = {'r', REQUIRED_VAL},
		[opt_P] = {'P', MULTI_VAL | REQUIRED_VAL},
		[opt_i] = {'i', OPTIONAL_VAL},
		[opt_m] = {'m', OPTIONAL_VAL},
		[opt_n] = {'n', OPTIONAL_VAL},
		[opt_p] = {'p', OPTIONAL_VAL},
		[opt_u] = {'u', OPTIONAL_VAL},
		[opt_C] = {'C', OPTIONAL_VAL},
		[opt_T] = {'T', OPTIONAL_VAL},
		[opt_U] = {'U', OPTIONAL_VAL},
		[opt_t] = {'t', REQUIRED_VAL | INT_VAL},
		[opt_inv] = {'\0', 0},
	};
	int arg1;	/* index of 1st non-option arg */
	struct namespace nsp[] = {
		[opt_i] = {CLONE_NEWIPC,	"/proc/%u/ns/ipc",	-1},
		[opt_m] = {CLONE_NEWNS,		"/proc/%u/ns/mnt",	-1},
		[opt_n] = {CLONE_NEWNET,	"/proc/%u/ns/net",	-1},
		[opt_p] = {CLONE_NEWPID,
			"/proc/%u/ns/pid_for_children",			-1},
		[opt_u] = {CLONE_NEWUTS,	"/proc/%u/ns/uts",	-1},
		[opt_C] = {CLONE_NEWCGROUP,	"/proc/%u/ns/cgroups",	-1},
		[opt_T] = {CLONE_NEWTIME,
			"/proc/%u/ns/time_for_children",		-1},
		[opt_U] = {CLONE_NEWUSER,	"/proc/%u/ns/user",	-1},
	};
	int setns_flags = 0;
	int unshare_flags = 0;
	int unshared = 0;
	int nspidfd = -1;
	int nspidfd_type = CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET |
		CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWCGROUP | CLONE_NEWTIME |
		CLONE_NEWUSER;
	/* Array of required src=>tgt pairs to be bind mounted: */
	struct src_tgt mnt[opt_U - opt_i + 1];
	int mntc = 0;	/* actual number of elements in mnt[] */
	pid_t pid, oldns_pid = -1, runner_pid = -1, wpid;
	int to_oldns_pipefd[2] = {-1, -1};
	int from_oldns_pipefd[2] = {-1, -1};
	int runner_pipefd[2] = {-1, -1};
	char ping = '!';
	int wstatus = 0;

	/* Get progname as basename(argv[0]): */
	if (argv[0] != NULL && argv[0][0] != '\0') {
		progname = argv[0];
		for (chp = argv[0]; *chp != '\0'; chp++)
			if (*chp == '/')
				progname = chp + 1;
	};

	/* If we are run with "-" in front of name, set loginshell flag: */
	if (argv[0] != NULL && argv[0][0] == '-')
		o[opt_l].cnt++;

	/* Parse options: */
	arg1 = getoptv(o, argv);

	/* Only -e=^H and -e=^? are supported at the moment: */
	if (o[opt_e].cnt) {
		if (str_eq(o[opt_e].val, "^H")) o[opt_e].ival = '\010';
		else if (str_eq(o[opt_e].val, "^?")) o[opt_e].ival = '\177';
		else {
			warn("unsupported -e=%s value\n", o[opt_e].val);
			o[opt_inv].cnt++;
		};
	};
	/* when -h or invalid option is specified, print USAGE and exit: */
	if (o[opt_h].cnt || o[opt_inv].cnt) {
		fprintf(o[opt_inv].cnt ? stderr : stdout,
			"USAGE: %s [opts ...] [--] prog_to_run [args ...]\n"
			"\n"
			" opts:\n"
			" -e=C    set tty erase char to C.\n"
			" -h      print this USAGE message\n"
			" -l      login shell mode (prepend '-' to prog)\n"
			" -r=DIR  chroot to DIR before setns()/unshare() if"
				" not creating new user\n"
			"         namespace or after setns()/unshare()"
				" otherwise\n"
			" -P=XYZ  putenv(XYZ) into new environment, e.g."
				" -P=TERM=xterm to set TERM\n"
			"         variable, or -P=TERM to remove TERM from"
				" environment\n"
			" -i[=NS] create/enter IPC namespace NS\n"
			" -m[=NS] create/enter mount namespace NS\n"
			" -n[=NS] create/enter network namespace NS\n"
			" -p[=NS] create/enter PID namespace NS\n"
			" -u[=NS] create/enter UTS namespace NS\n"
			" -C[=NS] create/enter cgroup namespace NS\n"
			" -T[=NS] create/enter time namespace NS\n"
			" -U[=NS] create/enter user namespace NS\n"
			" -t=PID  enter PID's namespaces not covered by"
				" -imnpuCTU options\n"
			"\n"
			"For -x[=NS] options, specifying -x once without"
				" parameter means create new NS;\n"
			"* specifying -x=NS once with parameter means enter"
				" the given NS;\n"
			"* specifying both -x and -x=NS (eg. -xx=NS) means"
				" create new namespace\n"
			"  and mount it onto the given NS file\n"
			, progname);
		if (!o[opt_inv].cnt) ret = EXIT_SUCCESS;
		goto EXIT0;
	};

	/* Write down mount src/tgt for all requested bind mounts: */
	pid = getpid();
	for (i = opt_i; i <= opt_U; i++)
		if (req_src_tgt(mnt + mntc, o + i, nsp[i].fmt, (unsigned)pid))
			mntc++;

	/* Fix tty's erase char setting if -e option was given: */
	if (o[opt_e].cnt) {
		/* get original tty settings: */
		if (tcgetattr(STDIN_FILENO, &ttios) != 0) {
			if (errno == ENOTTY)
				warn("stdin is not a tty\n");
			else
				warn("tcgetaddr(stdin): %m\n");
		} else if (ttios.c_cc[VERASE] != o[opt_e].ival) {
			/* change erase char: */
			ttios.c_cc[VERASE] = o[opt_e].ival;
			/* change tty settings: */
			if (tcsetattr(STDIN_FILENO, TCSANOW, &ttios) != 0)
				warn("tcsetaddr(stdin): %m\n");
			else
				info("set tty erase=%s\n", o[opt_e].val);
		};
	};

	/* Start oldns child: */
	if (pipe(to_oldns_pipefd) != 0) {
		err("pipe(to_oldns_pipefd): %m\n");
		goto EXIT1;
	};
	if (pipe(from_oldns_pipefd) != 0) {
		err("pipe(from_oldns_pipefd): %m\n");
		goto EXIT1;
	};
	oldns_pid = fork();
	if (oldns_pid == -1) {
		err("fork(oldns): %m\n");
		goto EXIT1;
	} else if (oldns_pid == 0) {
		/* Executing in oldns child process: */
		ret = EXIT_SUCCESS;
		/* Close write side of "to" pipe: */
		close(to_oldns_pipefd[1]);
		to_oldns_pipefd[1] = -1;
		/* Close read side of "from" pipe: */
		close(from_oldns_pipefd[0]);
		from_oldns_pipefd[0] = -1;
		/* Free option values: */
		freeoptv(o);
		/* Wait-for/execute cmds from parent and exit: */
		return oldns_main(to_oldns_pipefd[0], from_oldns_pipefd[1],
			mntc, mnt);
	} else {
		/* Close read side of "to" pipe: */
		close(to_oldns_pipefd[0]);
		to_oldns_pipefd[0] = -1;
		/* Close write side of "from" pipe: */
		close(from_oldns_pipefd[1]);
		from_oldns_pipefd[1] = -1;
		/* Cleanup list of bind mounts in parent process, 'cause it's
		 * been successfully delegated to oldns child: */
		while (mntc > 0)
			free(mnt[--mntc].src);
	};

	/* Open files for specified namespaces and populate unshare_flags,
	 * setns_flags and nspidfd_type: */
	for (i = opt_i; i <= opt_U; i++) {
		nsp[i].fn = o[i].val;
		if (o[i].cnt > o[i].vcnt) {
			unshare_flags |= nsp[i].type;
		} else if (o[i].cnt == o[i].vcnt && o[i].vcnt > 0
				&& nsp[i].fn != NULL) {
			if (nsp[i].fn[0] != '\0') {
				nsp[i].fd = open(nsp[i].fn, O_RDONLY);
				if (nsp[i].fd == -1) {
					err("open(%s, O_RDONLY): %m\n",
						nsp[i].fn);
					goto EXIT1;
				} else {
					/* Add nsp[i].type to setns_flags: */
					setns_flags |= nsp[i].type;
					/* Remove nsp[i].type from
					 * nspidfd_type: */
					nspidfd_type &= ~nsp[i].type;
				};
			} else {
				/* Remove nsp[i].type from nspidfd_type: */
				nspidfd_type &= ~nsp[i].type;
			};
		};
	};

	/* Open pidfd for PID specified in -t option: */
	if (o[opt_t].cnt) {
		nspidfd = syscall(SYS_pidfd_open, o[opt_t].ival, 0);
		if (nspidfd == -1) {
			err("pidfd_open(%u, 0): %m\n",
				(unsigned)o[opt_t].ival);
			goto EXIT1;
		} else {
			/* Add nspidfd_type to setns_flags: */
			setns_flags |= nspidfd_type;
		};
	};

	/* When creating new user_namespace (CLONE_NEWUSER flag set), don't
	 * chroot() _before_ unshare(); instead postpone it until _after_ the
	 * unshare() call.
	 * `man 2 unshare` citation:
	 * EPERM (since Linux 3.9)
	 *    CLONE_NEWUSER was specified in flags and the caller is in a
	 *    chroot environment (i.e., the caller's root directory does not
	 *    match the root directory of the mount namespace in which it
	 *    resides).
	 *
	 * This concerns _entering_ user name space too. When you chroot()
	 * and do nsenter(), you end up back at the old / dir, so you need to
	 * do chroot() again (or simply do it once _after_ nsenter():
	 *
	 * nsrun: changed root to /jail
	 * nsrun: changed uid:gid 0/0/0/3217796584:0/0/0/0 => 0:0
	 * nsrun: dropped 10 supplementary groups
	 * nsrun: =ep
	 * nsrun: changed root to /jail
	 * nsrun: executing /bin/bash
	 */

	/* Enter namespaces indicated by open file descriptors in nsp[].fd: */
	for (i = opt_i; i <= opt_U; i++) {
		if (nsp[i].fd == -1) continue;
		if (setns(nsp[i].fd, nsp[i].type) != 0) {
			err("setns(%s, %x): %m\n", nsp[i].fn, nsp[i].type);
			goto EXIT1;
		};
		close(nsp[i].fd);
		nsp[i].fd = -1;
	};

	/* Enter namespaces indicated by nspidfd/nspidfd_type: */
	if (nspidfd != -1) {
		if (setns(nspidfd, nspidfd_type) != 0) {
			err("setns(pid %i, %x): %m\n",
				o[opt_t].ival, nspidfd_type);
			goto EXIT1;
		};
		close(nspidfd);
		nspidfd = -1;
	};

	/* Get current uids/gids: */
	cr1 = getugids();
	/* Desired uids/gids are euid/egid: */
	cr2.ruid = cr2.euid = cr2.svuid = cr2.fsuid = cr1.euid;
	cr2.rgid = cr2.egid = cr2.svgid = cr2.fsgid = cr1.egid;
	/* If cr1 != cr2, change uids/gids to desired ones: */
	if (!ugids_eq(&cr1, &cr2)) {
		if (setugids(cr2) == 0) {
			info("changed u:gid %u/%u/%u/%u:%u/%u/%u/%u => %u:%u\n",
				cr1.ruid, cr1.euid, cr1.svuid, cr1.fsuid,
				cr1.rgid, cr1.egid, cr1.svgid, cr1.fsgid,
				cr2.euid, cr2.egid);
		} else {
			/* If setting cr2 failed, get actual uids/gids: */
			cr2 = getugids();
		};
	};
	/* Get number of supplementary groups: */
	ngroups = getgroups(0, NULL);
	if (ngroups < 0)
		warn("getgroups(0, NULL): %m\n");
	else if (ngroups > 0) {
		/* Drop all supplementary groups: */
		if (setgroups(0, NULL) != 0)
			warn("setgroups(0, NULL): %m\n");
		else
			info("dropped %i supplementary groups\n", ngroups);
	};

	/* Create (unshare) new namespaces: */
	if (unshare_flags) {
		if (unshare(unshare_flags) == 0)
			unshared = unshare_flags;
		else {
			err("unshare(%x): %m\n", unshare_flags);
			goto EXIT1;
		};
	};

	/* XXX: Do chroot()/pivot_root() immediately after creating/entering
	 * new namespaces? */

	/* Fork runner child: */
	if (pipe(runner_pipefd) != 0) {
		err("pipe(runner_pipefd): %m\n");
		goto EXIT1;
	};
	runner_pid = fork();
	if (runner_pid == -1) {
		err("fork(runner): %m\n");
		goto EXIT1;
	} else if (runner_pid == 0) {
		/* Runner child doesn't have any use for pipe to/from its
		 * 'oldns' sibling: */
		close(to_oldns_pipefd[1]);
		to_oldns_pipefd[1] = -1;
		close(from_oldns_pipefd[0]);
		from_oldns_pipefd[0] = -1;
		/* Close write side of runner pipe: */
		close(runner_pipefd[1]);
		runner_pipefd[1] = -1;
		/* Wait for ping from parent: */
		if (!readall(runner_pipefd[0], &ping, 1,
				"pipe from runner's parent"))
			goto EXIT1;
		debug("runner received '%.1s' cmd\n", &ping);
		switch (ping) {
		case 'r':
			break;
		default:
			err("invalid runner cmd '%.1s'\n", &ping);
			goto EXIT1;
		};
		/* After we're done reading commands from parent,
		 * close read side of pipe too, and go run: */
		close(runner_pipefd[0]);
		runner_pipefd[0] = -1;

		return runner_main(argv + arg1, o, nsp, unshared, cr2);
	} else {
		/* Parent side after fork:
		 * 1. close read side of runner pipe;
		 * 3. ask oldns child to do planned bind mounts;
		 * 4. ask oldns child to write uid_map/setgroups and gid_map
		 *    for the runner_pid (if necessary);
		 * 5. send 'q' command and wait for oldns child to exit;
		 * 6. send 'r' command to runner to start it;
		 * 7. wait for runner completion and return its exit code.
		 */
		close(runner_pipefd[0]);
		runner_pipefd[0] = -1;

		/* Send 'm' ("do bind mounts") command: */
		ping = 'm';
		if (!writeall(to_oldns_pipefd[1], &ping, 1,
				"pipe to oldns"))
			goto EXIT1;
		/* Receive 'm' results: */
		if (!readall(from_oldns_pipefd[0], (char *)&ret,
				sizeof(ret), "pipe from oldns")
				|| ret != EXIT_SUCCESS)
			goto EXIT1;
		if (unshare_flags & CLONE_NEWUSER) {
			/* Send 'w' ("write g:uid maps") command: */
			ping = 'w';
			if (!writeall(to_oldns_pipefd[1], &ping, 1,
					"pipe to oldns"))
				goto EXIT1;
			if (!writeall(to_oldns_pipefd[1], (char *)&runner_pid,
					sizeof(runner_pid), "pipe to oldns"))
				goto EXIT1;
			/* Receive 'w' results: */
			if (!readall(from_oldns_pipefd[0], (char *)&ret,
					sizeof(ret), "pipe from oldns")
					|| ret != EXIT_SUCCESS)
				goto EXIT1;
		};
		/* Send 'q' ("quit") command: */
		ping = 'q';
		if (!writeall(to_oldns_pipefd[1], &ping, 1, "pipe to oldns"))
			goto EXIT1;
		/* Wait for oldns_pid exit: */
		while ((wpid = waitpid(oldns_pid, &wstatus, 0)) ==
				oldns_pid) {
			if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus))
				break;
		};
		if (wpid != oldns_pid)
			warn("waitpid(%u(oldns)): %m\n", oldns_pid);
#ifdef DEBUG
		else {
			fprintf(stdout, "%s: oldns ", progname);
			if (WIFEXITED(wstatus))
				fprintf(stdout, "exited with %u\n",
					WEXITSTATUS(wstatus));
			else if (WIFSIGNALED(wstatus))
				fprintf(stdout, "terminated by signal %u\n",
					WTERMSIG(wstatus));
			else
				fprintf(stdout, "exited somehow\n");
		};
#endif
		/* After oldns quits, we don't need its pipes anymore: */
		close(to_oldns_pipefd[1]);
		to_oldns_pipefd[1] = -1;
		close(from_oldns_pipefd[0]);
		from_oldns_pipefd[0] = -1;

		/* Send 'r' to runner child after oldns finishes: */
		ping = 'r';
		if (!writeall(runner_pipefd[1], &ping, 1, "pipe to runner")) {
			kill(runner_pid, SIGKILL);
			goto EXIT1;
		}

		/* Wait for runner child to exit and that's it: */
		while ((wpid = waitpid(runner_pid, &wstatus, 0))
				== runner_pid) {
			if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) break;
		};
		if (wpid != runner_pid) {
			err("waitpid(%u(runner)): %m\n", runner_pid);
			ret = EXIT_FAILURE;
		} else if (WIFEXITED(wstatus)) {
			ret = WEXITSTATUS(wstatus);
		} else if (WIFSIGNALED(wstatus)) {
			/* Commit suicide with the same weapon that killed
			 * our beloved child: */
			kill(pid, WTERMSIG(wstatus));
		};

		goto EXIT0;
	};


EXIT0:	if (nspidfd != -1)
		close(nspidfd);
	for (i = opt_i; i <= opt_U; i++) {
		if (nsp[i].fd != -1)
			close(nsp[i].fd);
	};
	for (i = 0; i <= 1; i++) {
		if (to_oldns_pipefd[i] != -1)
			close(to_oldns_pipefd[i]);
		if (from_oldns_pipefd[i] != -1)
			close(from_oldns_pipefd[i]);
		if (runner_pipefd[i] != -1)
			close(runner_pipefd[i]);
	};
	if (runner_pid != -1 && runner_pid != 0)
		kill(runner_pid, SIGKILL);
	if (oldns_pid != -1 && oldns_pid != 0)
		kill(oldns_pid, SIGKILL);
	while (mntc > 0) {
		if (mnt[--mntc].src != NULL)
			free(mnt[mntc].src);
	};
	freeoptv(o);
	return ret;

EXIT1:	ret = EXIT_FAILURE;
	goto EXIT0;
};

/* vi:set sw=8 ts=8 noet tw=79: */
