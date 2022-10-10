#!/bin/sh
#
# Setup a chroot jail for firefox/telegram.
#
# RATIONALE:
#
# 1. firefox MUST operate in chroot to deny access to private data and real
#    system IDs (all files in /etc/ that contain UUIDs, unique usernames and
#    passwords, WiFi APNs, /etc/machine-id etc)
#
# 2. firefox MUST be unable to obtain real system's IP/MAC addresses, hostname
#    and see processes and network traffic running outside its jail, therefore
#    it MUST be run in separate PID and net namespaces.
#
# 3. firefox SHOULD be unable to list devices on PCI bus, so /proc bind mount
#    in chroot SHOULD have /proc/bus/pci mounted over by an empty filesys with
#    only an _empty_ /proc/bus/pci/devices file present (this way lspci would
#    work in chroot, just return an empty list).
#
# 4. setup via mkchroot.sh (minimal, with required shared libs only) wasn't
#    successfull (firefox crashed in chroot no matter what OpenGL/EGL devices
#    it was permitted to see), so I decided to drop that approach and perform a
#    "minimal install of Gentoo in chroot".
#
# 5. in order to minimize waste of space, during setup/emerge/update only,
#    chroot's /var/tmp/portage (mode 0775 portage:portage), /var/db/repos,
#    /var/cache/distfiles (and optionally /var/cache/binpkgs and /usr/src) will
#    be bind mounted from the outer system.

# Default Gentoo download server and mirror:
SRV0="https://distfiles.gentoo.org"
DSRV="https://bouncer.gentoo.org/fetch/root/all"
# Default inmate user name and uid:
JUSR="foobar"
JUID0=60000

# Accepts 1 or 2 arguments:
#   die [errcode] message_pt1 [message_pt2 ...]
# Prints error message and exits with errcode (or 1):
die() {
    E="$?"
    case "z$E" in z0)E=1;; esac
    if [ 0 -lt $# ] && expr "z$1" : 'z[0-9][0-9]*$' >/dev/null ; then
	E="$1"
	shift
    fi
    if [ 0 -lt $# ] ; then
	echo "ERROR:" "$@" 1>&2
    fi
    exit "$E"
}

# Derive ARCH and ST3V from current Gentoo profile:
PROF=`readlink /etc/portage/make.profile`
case "z$ARCH" in z)
	case "z$PROF" in
	z*/x86/*)	ARCH="x86";;
	z*/amd64/*)	ARCH="amd64";;
	z?*)		die "unsupported ARCH in profile $PROF";;
	z)		die;;
	esac
	;;
esac
case "z$ST3V" in z)
	case "z$PROF" in
	z*/x86/*/selinux*)
		ST3V="i686-hardened-selinux-openrc"
		;;
	z*/x86/*/musl*)
		ST3V="i686-musl"
		;;
	z*/x86/*)
		ST3V="i686-hardened-openrc"
		;;
	z*/amd64/*/selinux*)
		ST3V="amd64-hardened-nomultilib-selinux-openrc"
		;;
	z*/amd64/*/musl*)
		ST3V="amd64-musl-hardened"
		;;
	z*/amd64/*)
		ST3V="amd64-hardened-nomultilib-openrc"
		;;
	z?*)	die "unsupported profile: $PROF"
		;;
	z)	die
		;;
	esac
	;;
esac

# USAGE: chmod_chown FILENAME MODE OWNER
chmod_chown() {
	[ -e "$1" ] || die
	case "z$2" in
	z0[0-7][0-7][0-7]);&
	z0[0-7][0-7][0-7][0-7])
		chmod "$2" "$1" || die;;
	esac
	case "z$3" in
	z*:*)
		chown "$3" "$1" || die;;
	esac
}

# Create all nonexistent dirs in path except for last path component:
mkdir_1() {
	if [ -e "${1%/*}" ]; then
		[ -d "${1%/*}" ] || \
			die "${1%/*} exists but is not a directory"
	else
		mkdir -p "${1%/*}" || die
	fi
}

# USAGE: mkdev /jail/dir
# Create very minimal dev subdirectory in the specified jail dir:
mkdev() {
	DST="$1"
	case "z$DST" in
	z/|z)	die "invalid destination directory '$DST'";;
	esac
	[ -d "$DST" ] || die "destination '$DST' is not a directory"
	DST="${DST%/}";			# strip trailing slash
	while read TYP FN C D E F G; do
		# Skip empty lines and comments:
		case "z$TYP" in z\#*|z) continue;; esac
		# Check for abs/rel names:
		case "z$FN" in
		z/*)	;;	# OK
		z*)	die "Invalid CONTENTS: $TYP $FN $C $D $E $F $G";;
		esac
		F2="$DST$FN"
		# Create dirs/symlinks/device nodes:
		case "z$TYP" in
		zdir)	if ( [ -h "$F2" ] || [ -e "$F2" ] ) \
			&& ! [ -d "$F2" ]; then
				rm -f "$F2" || die "cannot rm $F2";
			fi
			[ -d "$F2" ] || mkdir -p "$F2" \
				|| die "cannot mkdir $F2"
			chmod_chown "$F2" "$C" "$D"
			;;
		zsym)	if [ "z$C" != "z->" ] || [ "z$D" == "z" ]; then
				die "Invalid CONTENTS: $TYP $FN $C $D $E $F $G"
			fi
			if [ -h "$F2" ] || [ -e "$F2" ]; then
				rm -f "$F2" || die "cannot rm $F2";
			fi
			mkdir_1 "$F2"
			ln -s "$D" "$F2" || die
			;;
		znod)	if [ -h "$F2" ]; then rm -f "$F2" || die; fi
			if [ -d "$F2" ]; then rmdir "$F2" || die; fi
			if [ -e "$F2" ]; then rm -f "$F2" || die; fi
			mkdir_1 "$F2"
			case "z$C" in
			z[bcu])	mknod "$F2" "$C" "$D" "$E" || die
				chmod_chown "$F2" "$F" "$G"
				;;
			z[p])	mknod "$F2" "$C" || die
				chmod_chown "$F2" "$D" "$E"
				;;
			z*)	die "ERROR: unknown node type '$C' for $F2";;
			esac
			;;
		z*)	die "Invalid CONTENTS: $TYP $FN $C $D $E $F $G";;
		esac
	done <<CONTENTS
dir /dev	0755
dir /dev/mqueue	0755
dir /dev/pts	0755
dir /dev/shm	0755
nod /dev/null	c	1	3	0666
nod /dev/zero	c	1	5	0666
nod /dev/full	c	1	7	0666
nod /dev/random	c	1	8	0666
nod /dev/urandom	c	1	9	0666
nod /dev/tty		c	5	0	0666	root:tty
nod /dev/console	c	5	1	0600
nod /dev/ptmx	c	5	2	0666	root:tty
sym /dev/fd	->	../proc/self/fd
sym /dev/stdin	->	../proc/self/fd/0
sym /dev/stdout	->	../proc/self/fd/1
sym /dev/stderr	->	../proc/self/fd/2
CONTENTS
}

NL="
"
USAGE="USAGE: ${0##*/} [opts] /path/to/jail [action]
where action is one of:
  create    setup Gentoo jail
  firefox   setup Gentoo jail and emerge firefox
  telegram  setup jail and emerge telegram-desktop
  update    update Gentoo in jail
  enter     start shell in jail as regular user
  root      start shell as root
opts: one or more of the next options:
  -r        rsync /var/db/repos/ to jail instead of mount
  -s        don't mount host's /usr/src onto jail
  --        end of options"

# Get/validate mkdev.sh parameters:
OPT_R=0
OPT_S=0
A=0
while [ "z$A" != "z1" ] && [ "z$#" != "z0" ] ; do
	case "z$1" in
		z-r)	OPT_R=1;shift;;
		z-s)	OPT_S=1;shift;;
		z--)	A=1;	shift;;
		z-*)	die "invalid option: $1$NL$USAGE";;
		z?*)	A=1;;
	esac
done
case "z$1" in
z)	die "jail dir parameter required";;
z/)	die "jail dir cannot be /";;
esac
if ! [ -e "$1" ]; then die "$1 does not exist"; fi
if ! [ -d "$1" ]; then die "$1 is not a directory"; fi

# USAGE: chdir_jail path/to/jailX
#
# on return:
#	JAIL	- /abs/path/to/jailX
#	JNAME	- jail_basename
#	JNET    - 0 <= JNET <= 255, (192.168.X.0/24)
#	JUID	- 60000+X (JUID0+X)
chdir_jail() {
	# Change to jail directory and get its absname:
	cd "$1" || die
	JAIL="`pwd`"
	case "z$JAIL" in
	z) die "'pwd' error";;
	z/) die "jail dir cannot be /";;
	esac

	# Strip trailing slash:
	JAIL="${JAIL%/}"

	# Strip leading dirname:
	JNAM="${JAIL##*/}"

	# Convert last digits in jail name (if any) to component X of
	# jail's subnet (192.168.X.0/24):
	X=`printf '%s' "$JNAM" \
		| sed -nr 's/^(.*[^0-9])?([0-9]+)[^0-9]*$/\2/p'`
	case "z$X" in z) X=0;; esac
	if [ "$X" -gt 255 ]; then
		die "invalid JNET: 192.168.$X.0/24";
	fi
	JNET="$X"
	JUID=`expr "$JUID0" + "$X"`
	printf '%s: using 192.168.%s.0/24 net, ns%s and uid %i for %s\n' \
		"${0##*/}" "$JNET" "$JNET" "$JUID" "$JAIL"

	# Unmount jail subdirectories/submounts:
	while read A B C; do
		case "z$B" in
		z"$JAIL"/*)
			umount --recursive "$B" || die
			;;
		esac
	done </proc/self/mounts
}

# USAGE: get_jail_jnam [JAIL [JNAM]]
get_jail_jnam() {
	# Check that $1/$JAIL is valid:
	case "z$1" in z?*) JAIL="$1";; esac
	case "z$JAIL" in z|z/) JAIL=""; return 1;; esac
	# Check that we can chdir to $JAIL:
	if ! pushd "$JAIL" >/dev/null; then JAIL=""; return 1; fi
	# Check that _real_ dirname of $JAIL is valid:
	JAIL="`pwd`"
	popd >/dev/null
	case "z$JAIL" in z|z/) JAIL=""; return 1;; esac
	# Strip trailing slash:
	JAIL="${JAIL%/}"

	# Get JNAM:
	case "z$2" in
	z)	JNAM="${JAIL##*/}";;
	z?*)	JNAM="$2"
	esac
}

__umount_jail_var() {
	case "z$OPT_S" in
	z1)	;;
	z*)	umount --recursive "$1/usr/src";;
	esac
	umount --recursive "$1/var/cache/binpkgs"
	umount --recursive "$1/var/cache/distfiles"
	case "z$OPT_R" in
	z1)	;;
	z*)	umount --recursive "$1/var/db/repos";;
	esac
	umount --recursive "$1/var/tmp/portage"
	rm -rf /var/tmp/portage-"$2"
}

# USAGE: umount_jail_var [JAIL [JNAM]]
umount_jail_var() {
	if ! get_jail_jnam "$1" "$2"; then return; fi

	# With 'trap umount_jail_var EXIT SIGINT', umount_jail_var()
	# is called twice in bash and ash. UMNTD flag is a workaround
	# for silencing "xxx not mounted" error messages:
	case "z$UMNTD" in
	z1)	__umount_jail_var "$JAIL" "$JNAM" 2>/dev/null;;
	z*)	__umount_jail_var "$JAIL" "$JNAM";;
	esac
	UMNTD=1
}

# USAGE: mount_jail_var [JAIL [JNAM]]
mount_jail_var() {
	if ! get_jail_jnam "$1" "$2"; then return; fi

	# Setup automatic unmount on error or signal.
	# In ash 'trap foo EXIT' won't trigger on SIGINT, while
	# 'trap foo EXIT SIGINT' will call foo() twice. There are
	# 2 workarounds:
	# * use 'foo() has already been triggered' flag in foo()
	# * define empty function bar() and set 'trap bar SIGINT'
	#   alongside 'trap foo EXIT'
	trap umount_jail_var EXIT SIGINT SIGHUP SIGTERM

	# Mount/rsync /var/db/repos:
	case "z$OPT_R" in
	z1)	# rsync /var/db/repos:
		rsync -auxHAXSUU -iF /var/db/repos/ \
			"$JAIL/var/db/repos/" || die
		;;
	z*)	# mount /var/db/repos:
		mount --bind /var/db/repos "$JAIL/var/db/repos" || die
		mount --make-slave "$JAIL/var/db/repos" || die
		;;
	esac

	# Mount /var/tmp/portage:
	mkdir /var/tmp/portage-"$JNAM"
	chown portage:portage /var/tmp/portage-"$JNAM"
	chmod 0755 /var/tmp/portage-"$JNAM"
	mkdir "$JAIL/var/tmp/portage" 2>/dev/null
	chown portage:portage "$JAIL/var/tmp/portage"
	chmod 0755 "$JAIL/var/tmp/portage"
	mount --bind /var/tmp/portage-"$JNAM" "$JAIL/var/tmp/portage" || die
	mount --make-slave "$JAIL/var/tmp/portage" || die

	# Mount /var/cache/distfiles:
	mount --bind /var/cache/distfiles "$JAIL/var/cache/distfiles" || die
	mount --make-slave "$JAIL/var/cache/distfiles" || die

	# Mount /var/cache/binpkgs:
	mount --bind /var/cache/binpkgs "$JAIL/var/cache/binpkgs" || die
	mount --make-slave "$JAIL/var/cache/binpkgs" || die

	# Optionally mount /usr/src:
	case "z$OPT_S" in
	z1)	;;
	z*)	# mount /usr/src:
		mount --rbind /usr/src "$JAIL/usr/src" || die
		mount --make-rslave "$JAIL/usr/src" || die
	esac
}

# USAGE: mkjail path/to/jail ARCH ST3V SRV0 DSRV JUSR firefox
#    or  mkjail path/to/jail ARCH ST3V SRV0 DSRV JUSR telegram
#    or  mkjail path/to/jail ARCH ST3V SRV0 DSRV JUSR
mkjail() {
	chdir_jail "$1"
	[ "z$JAIL" != "z" ] || die
	[ "z$JNAM" != "z" ] || die
	[ "z$JNET" != "z" ] || die
	[ "z$JUID" != "z" ] || die
	expr match "$JUID" '[0-9][0-9]*$' >/dev/null \
		|| die "invalid uid: $JUID"
	ARCH="$2"
	ST3V="$3"
	SRV0="$4"
	DSRV="$5"
	JUSR="$6"
	APP="$7"
	expr match "$JUSR" '[a-zA-Z_][a-zA-Z0-9_]*$' >/dev/null \
		|| die "invalid user name: $JUSR"

	# Clean all files/directories in jail:
	find . -mount -maxdepth 1 ! -name . -execdir rm -rf '{}' '+'

	# Download latest-stage3-xxx.txt file, e.g.
	# latest-stage3-amd64-hardened-nomultilib-selinux-openrc.txt:
	#   # Latest as of Sun, 20 Mar 2022 18:00:03 +0000
	#   # ts=1647799203
	#   20220315T091810Z/stage3-amd64-hardened-nomultilib-selinux-openrc-20220315T091810Z.tar.xz 221397584
	LST3=`wget -O- \
		"$SRV0"/releases/"$ARCH"/autobuilds/latest-stage3-"$ST3V".txt`
	[ "z$?" = "z0" ] || die

	# Find filename/URL of latest stage3-xxx.tar.xz:
	TXZ=""
	while read A B; do
		case "z$A" in
		z"#"*)	continue;;
		z*stage3*"$ST3V"*.tar.xz)
			TXZ="$A"
			break;;
		esac
	done <<EOF
$LST3
EOF
	[ "z$TXZ" != "z" ] || die "cannot find latest stage3 tar.xz"

	# Basename of tar.xz:
	TXZN="${TXZ##*/}"

	# Download tar.xz and signature files:
	wget -cO "/var/tmp/$TXZN" \
		"$DSRV"/releases/"$ARCH"/autobuilds/"$TXZ" \
		|| die
	wget -O "/var/tmp/$TXZN".asc \
		"$DSRV"/releases/"$ARCH"/autobuilds/"$TXZ".asc \
		|| die

	# Verify signature:
	gpg --verify "/var/tmp/$TXZN".asc || die

	# Extract tar.xz in jail dir:
	printf 'Extracting %s\n' "$TXZN"
	tar xpJf "/var/tmp/$TXZN" --acls --xattrs --xattrs-include='*.*' \
		--numeric-owner --selinux --atime-preserve=system \
		|| die

	# Remove dev subdirectory and re-create it from scratch:
	if [ -e ./dev ]; then
		rm -rf ./dev || die
	fi
	printf 'Re-creating minimal %s\n' "$JAIL/dev"
	mkdev ./

	# Do minimal necessary configuration of portage in jail:
	case "z$APP" in
	zfirefox*)
		cat >"$JAIL/etc/portage/package.use/local.use" <<EOF || die
media-libs/libglvnd	X
media-libs/libvpx	postproc
x11-libs/cairo		X
x11-libs/libxkbcommon	X
EOF
		case "z$ARCH" in zx86)
			cat >>"$JAIL/etc/portage/package.use/local.use" \
				<<EOF || die
dev-lang/rust		cpu_flags_x86_sse2
net-libs/nodejs		cpu_flags_x86_sse2
EOF
			;;
		esac
		;;
	ztelegram*)
		cat >"$JAIL/etc/portage/package.use/local.use" <<EOF || die
dev-qt/qtgui		dbus jpeg
media-libs/libglvnd	X
media-video/ffmpeg	opus
sys-libs/zlib		minizip
x11-libs/libxkbcommon	X
EOF
		;;
	z*)	# both:
		cat >"$JAIL/etc/portage/package.use/local.use" <<EOF || die
dev-qt/qtgui		dbus jpeg
media-libs/libglvnd	X
media-libs/libvpx	postproc
media-video/ffmpeg	opus
sys-libs/zlib		minizip
x11-libs/cairo		X
x11-libs/libxkbcommon	X
EOF
		case "z$ARCH" in zx86)
			cat >>"$JAIL/etc/portage/package.use/local.use" \
				<<EOF || die
dev-lang/rust		cpu_flags_x86_sse2
net-libs/nodejs		cpu_flags_x86_sse2
EOF
			;;
		esac
		;;
	esac

	if [ -d "/var/db/repos/gentoo" ]; then
		cat >"$JAIL/etc/portage/repos.conf" <<EOF || die
[DEFAULT]
main-repo = gentoo

[gentoo]
location = /var/db/repos/gentoo
sync-type = rsync
sync-uri = rsync://rsync.gentoo.org/gentoo-portage
auto-sync = yes
sync-rsync-verify-jobs = 1
sync-rsync-verify-metamanifest = yes
sync-rsync-verify-max-age = 24
sync-openpgp-key-path = /usr/share/openpgp-keys/gentoo-release.asc
sync-openpgp-keyserver = hkps://keys.gentoo.org
sync-openpgp-key-refresh-retry-count = 40
sync-openpgp-key-refresh-retry-overall-timeout = 1200
sync-openpgp-key-refresh-retry-delay-exp-base = 2
sync-openpgp-key-refresh-retry-delay-max = 60
sync-openpgp-key-refresh-retry-delay-mult = 4
sync-webrsync-verify-signature = yes
EOF
	else
		die "no /var/db/repos/gentoo found, manual setup needed"
	fi

	# Set UTC as localtime (to avoid leaking local timezone to firefox):
	if [ -e "$JAIL/etc/localtime" ]; then
		rm -f "$JAIL/etc/localtime" || die
	fi
	ln -s ../usr/share/zoneinfo/UTC "$JAIL/etc/localtime" || die

	# Generate .inputrc for jail users (optional):
	cat >"$JAIL/root/.inputrc" <<'EOF' || die
$include /etc/inputrc
# alternate mappings for "up" and "down" to search the history
"\e[A": history-search-backward
"\eOA": history-search-backward
"\e[B": history-search-forward
"\eOB": history-search-forward
EOF
	cp -pr "$JAIL/root/.inputrc" "$JAIL/etc/skel/.inputrc" || die

	# Create /etc/resolv.conf in jail:
	printf 'nameserver %s\n' "192.168.$JNET.1" \
		>"$JAIL/etc/resolv.conf" || die

	# Mount /var/tmp/portage, /var/db/repos and /var/cache/distfiles:
	mount_jail_var "$JAIL" "$JNAM"

	# Generate C.UTF-8, en_US and en_US.UTF8 locales and set default
	# jail locale to C.UTF8 (not supported on musl):
	case "z$ST3V" in z*musl*);;
	z?*)
		cat >>"$JAIL/etc/locale.gen" <<EOF || die
en_US		ISO-8859-1
en_US.UTF-8	UTF-8
EOF
		nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" \
			/usr/sbin/locale-gen || die
		nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" \
			/usr/bin/eselect locale set C.UTF8 || die
		;;
	esac

	# Create inmate user/group in jail:
	nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" -P="LANG=C.UTF-8" \
		/usr/sbin/groupadd -g "$JUID" "$JUSR" || die
	nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" -P="LANG=C.UTF-8" \
		/usr/sbin/useradd -u "$JUID" -g "$JUID" "$JUSR" || die

	# Update sys-apps/portage first to avoid situatios like this:
	#
	# !!! The following installed packages are masked:
	# - sys-apps/portage-3.0.37::gentoo (masked by: package.mask)
	# /var/db/repos/gentoo/profiles/package.mask:
	# # Sam James <sam@gentoo.org> (2022-10-04)
	# # Please upgrade to >= portage-3.0.38.1 for binpkg fixes.
	# # bug #870283, bug #874771.
	nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" -P="LANG=C.UTF-8" \
		/usr/bin/emerge -uv1 sys-apps/portage || die

	# Emerge firefox/telegram in jail:
	TGTPKG=""
	case "z$APP" in
	zfirefox*)	TGTPKG="www-client/firefox";;
	ztelegram*)	TGTPKG="net-im/telegram-desktop";;
	esac
	if [ "z$TGTPKG" != "z" ]; then
		# Fetch files first:
		nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" -P="LANG=C.UTF-8" \
			/usr/bin/emerge -fv "$TGTPKG" || die
		nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" -P="LANG=C.UTF-8" \
			/usr/bin/emerge -v "$TGTPKG"
	fi

	# Umount /var/tmp/portage, /var/db/repos and /var/cache/distfiles:
	umount_jail_var "$JAIL" "$JNAM"
}

# USAGE: update_jail path/to/jail
update_jail() {
	chdir_jail "$1"
	[ "z$JAIL" != "z" ] || die
	[ "z$JNAM" != "z" ] || die
	[ "z$JNET" != "z" ] || die

	# Update /etc/resolv.conf in jail:
	printf 'nameserver %s\n' "192.168.$JNET.1" \
		>"$JAIL/etc/resolv.conf" || die

	# Mount /var/tmp/portage, /var/db/repos and /var/cache/distfiles:
	mount_jail_var "$JAIL" "$JNAM"

	# Do updates (emerge --update --deep --newuse @world):
	nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" -P="LANG=C.UTF-8" \
		/usr/bin/emerge -vuDN @world

	# Clean up unneeded packages after update (emerge --depclean):
	nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" -P="LANG=C.UTF-8" \
		/usr/bin/emerge -c

	# Umount /var/tmp/portage, /var/db/repos and /var/cache/distfiles:
	umount_jail_var "$JAIL" "$JNAM"
}

# USAGE: enter_jail path/to/jail JUSR
enter_jail() {
	chdir_jail "$1"
	[ "z$JAIL" != "z" ] || die
	[ "z$JNAM" != "z" ] || die
	[ "z$JNET" != "z" ] || die
	[ "z$JUID" != "z" ] || die
	expr match "$JUID" '[0-9][0-9]*$' >/dev/null \
		|| die "invalid uid: $JUID"
	JUSR="$2"
	expr match "$JUSR" '[a-zA-Z_][a-zA-Z0-9_]*$' >/dev/null \
		|| die "invalid user name: $JUSR"

	# Update /etc/resolv.conf in jail:
	printf 'nameserver %s\n' "192.168.$JNET.1" \
		>"$JAIL/etc/resolv.conf" || die

	# Transfer X11 MIT-MAGIC-COOKIE to JUSR:
	XDMAUTHD="/var/lib/xdm/authdir/authfiles/"
	XDMAUTHF="`ls -t "$XDMAUTHD" | head -n1`"
	MITMACOO="`xauth -f "$XDMAUTHD/$XDMAUTHF" list \
		| head -n1 | awk '{print $3}'`"
	case "z$JUSR" in
	zroot)	JXAUTH="$JAIL/root/.Xauthority";;
	z*)	JXAUTH="$JAIL/home/$JUSR/.Xauthority";;
	esac
	true >"$JXAUTH" || die
	xauth -f "$JXAUTH" add "192.168.$JNET.1:0" . "$MITMACOO" || die
	chown "$JUID:$JUID" "$JXAUTH" || die

	# Enter as JUSR:
	nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" -P="LANG=C.UTF-8" \
		-P="DISPLAY=192.168.$JNET.1:0" \
		/bin/su -w DISPLAY -Pl "$JUSR"
}

# USAGE: enter_jail_as_root path/to/jail
enter_jail_as_root() {
	chdir_jail "$1"
	[ "z$JAIL" != "z" ] || die
	[ "z$JNAM" != "z" ] || die
	[ "z$JNET" != "z" ] || die

	# Update /etc/resolv.conf in jail:
	printf 'nameserver %s\n' "192.168.$JNET.1" \
		>"$JAIL/etc/resolv.conf" || die

	# Entering as root is usually done for manual emerge/eselect etc,
	# therefore we need /var/db/repos and other mounts:
	mount_jail_var "$JAIL" "$JNAM"

	# Enter as root:
	nsrun -impuCTn=/run/netns/ns"$JNET" -r="$JAIL" -P="LANG=C.UTF-8" \
		/bin/su -Pl "root"

	# Umount /var/tmp/portage, /var/db/repos and /var/cache/distfiles:
	umount_jail_var "$JAIL" "$JNAM"
}

case "z$2" in
z|zcreate|zfirefox|ztelegram*)
	mkjail "$1" "$ARCH" "$ST3V" "$SRV0" "$DSRV" "$JUSR" "$2"
	;;
zupdate)
	update_jail "$1"
	;;
zenter)
	enter_jail "$1" "$JUSR"
	;;
zroot)
	enter_jail_as_root "$1"
	;;
z*)
	die "invalid action: $2$NL$USAGE"
	;;
esac

# vi:set ft=sh tw=79 sw=8 ts=8 noet:
