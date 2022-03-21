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

# Default Gentoo arch/profile:
ARCH="amd64"
PROF="hardened-nomultilib-selinux-openrc"
# Default Gentoo download server:
# DSRV="https://distfiles.gentoo.org"
DSRV="https://bouncer.gentoo.org/fetch/root/all"
# Default inmate user name and uid:
JUSR="foobar"
JUID=60000

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
			ln -s "$D" "$F2"
			;;
		znod)	if [ -h "$F2" ]; then rm -f "$F2" || die; fi
			if [ -d "$F2" ]; then rmdir "$F2" || die; fi
			if [ -e "$F2" ]; then rm -f "$F2" || die; fi
			mkdir_1 "$F2"
			case "z$C" in
			z[bcu])	mknod "$F2" "$C" "$D" "$E"
				chmod_chown "$F2" "$F" "$G"
				;;
			z[p])	mknod "$F2" "$C"
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

# Validate mkdev.sh parameters:
case "z$1" in
z)	die "jail dir parameter required";;
z/)	die "jail dir cannot be /";;
esac
if ! [ -e "$1" ]; then die "$1 does not exist"; fi
if ! [ -d "$1" ]; then die "$1 is not a directory"; fi

# Create safe tmp directory and ensure its autoremoval on exit:
TDIR="/tmp/tmp-mkgentoojail-$$"
if ! mkdir -m 0750 "$TDIR" ; then
    E="$?"
    echo "ERROR: mkdir $TDIR" 1>&2
    exit "$E"
fi
rm_rf_tdir() {
    rm -rf "$TDIR"
}
trap rm_rf_tdir EXIT

# USAGE: chdir_jail path/to/jail
#
# on return:
#	JAIL	- /abs/path/to/jail
#	JNAME	- jail_basename
#	JNET    - 192.168.X (0 <= X <= 255)
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
	JNET="192.168.$X"

	# Unmount jail subdirectories/submounts:
	while read A B C; do
		case "z$B" in
		z"$JAIL"/*)
			umount --recursive "$B" || die
			;;
		esac
	done </proc/self/mounts
}

# USAGE: mount_jail_var JAIL JNAM
mount_jail_var() {
	# Mount /var/tmp/portage:
	mkdir /var/tmp/portage-"$JNAM"
	chown portage:portage /var/tmp/portage-"$JNAM"
	chmod 0755 /var/tmp/portage-"$JNAM"
	mkdir "$JAIL/var/tmp/portage"
	chown portage:portage "$JAIL/var/tmp/portage"
	chmod 0755 "$JAIL/var/tmp/portage"
	mount --bind /var/tmp/portage-"$JNAM" "$JAIL/var/tmp/portage"
	mount --make-slave "$JAIL/var/tmp/portage"

	# Mount /var/db/repos:
	mount --bind /var/db/repos "$JAIL/var/db/repos"
	mount --make-slave "$JAIL/var/db/repos"

	# Mount /var/cache/distfiles:
	mount --bind /var/cache/distfiles "$JAIL/var/cache/distfiles"
	mount --make-slave "$JAIL/var/cache/distfiles"

	# Mount /var/cache/binpkgs:
	mount --bind /var/cache/binpkgs "$JAIL/var/cache/binpkgs"
	mount --make-slave "$JAIL/var/cache/binpkgs"

	# Mount /usr/src:
	mount --bind /usr/src "$JAIL/usr/src"
	mount --make-slave "$JAIL/usr/src"
}

# USAGE: umount_jail_var JAIL JNAM
umount_jail_var() {
	umount --recursive "$JAIL/usr/src"
	umount --recursive "$JAIL/var/cache/binpkgs"
	umount --recursive "$JAIL/var/cache/distfiles"
	umount --recursive "$JAIL/var/db/repos"
	umount --recursive "$JAIL/var/tmp/portage"
	rm -rf /var/tmp/portage-"$JNAM"
}

# USAGE: mkjail path/to/jail ARCH PROF DSRV JUSR JUID firefox
#    or  mkjail path/to/jail ARCH PROF DSRV JUSR JUID telegram
#    or  mkjail path/to/jail ARCH PROF DSRV JUSR JUID
mkjail() {
	chdir_jail "$1"
	[ "z$JAIL" != "z" ] || die
	[ "z$JNAM" != "z" ] || die
	[ "z$JNET" != "z" ] || die
	ARCH="$2"
	PROF="$3"
	DSRV="$4"
	JUSR="$5"
	JUID="$6"
	expr match "$JUSR" '[a-zA-Z_][a-zA-Z0-9_]*$' \
		|| die "invalid user name: $JUSR"
	expr match "$JUID" '[1-9][0-9]*$' \
		|| die "invalid uid: $JUID"

	# Clean all files/directories in jail:
	find . -mount -maxdepth 1 ! -name . -execdir rm -rf '{}' '+'

	# Download latest-stage3-xxx.txt file, e.g.
	# latest-stage3-amd64-hardened-nomultilib-selinux-openrc.txt:
	#   # Latest as of Sun, 20 Mar 2022 18:00:03 +0000
	#   # ts=1647799203
	#   20220315T091810Z/stage3-amd64-hardened-nomultilib-selinux-openrc-20220315T091810Z.tar.xz 221397584
	wget -O "$TDIR/STAGE3.txt" \
		"$DSRV"/releases/"$ARCH"/autobuilds/latest-stage3-"$ARCH"-"$PROF".txt \
		|| die

	# Find filename/URL of latest stage3-xxx.tar.xz:
	TXZ=""
	while read A B; do
		case "z$A" in
		z"#"*)	continue;;
		z*stage3*"$ARCH"-"$PROF"*.tar.xz)
			TXZ="$A"
			break;;
		esac
	done <"$TDIR/STAGE3.txt"
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
	rm -rf ./dev || die
	printf 'Re-creating minimal %s\n' "$JAIL/dev"
	mkdev ./

	# Do minimal necessary configuration of portage in jail:
	case "z$7" in
	zfirefox*)
		cat >"$JAIL/etc/portage/package.use/local.use" <<EOF
media-libs/libglvnd	X
media-libs/libvpx	postproc
x11-libs/cairo		X
EOF
		;;
	ztelegram*)
		cat >"$JAIL/etc/portage/package.use/local.use" <<EOF
dev-qt/qtgui		dbus jpeg
media-libs/libglvnd	X
media-video/ffmpeg	opus
sys-libs/zlib		minizip
x11-libs/libxkbcommon	X
EOF
		nsrun -impuCTn=/run/netns/ns0 -r="$JAIL" -P="LANG=C.UTF-8" \
			/usr/bin/emerge -av net-im/telegram-desktop
		;;
	z*)	# both:
		cat >"$JAIL/etc/portage/package.use/local.use" <<EOF
dev-qt/qtgui		dbus jpeg
media-libs/libglvnd	X
media-libs/libvpx	postproc
media-video/ffmpeg	opus
sys-libs/zlib		minizip
x11-libs/cairo		X
x11-libs/libxkbcommon	X
EOF
		;;
	esac
	if [ -d "/var/db/repos/gentoo" ]; then
		cat >"$JAIL/etc/portage/repos.conf" <<EOF
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

	# Generate C.UTF-8, en_US and en_US.UTF8 locales:
	cat >>"$JAIL/etc/locale.gen" <<EOF
en_US		ISO-8859-1
en_US.UTF-8	UTF-8
EOF
	locale-gen -d "$JAIL" -c "$JAIL/etc/locale.gen"

	# Set UTC as localtime (to avoid leaking local timezone to firefox):
	rm -f "$JAIL/etc/localtime"
	ln -s ../usr/share/zoneinfo/UTC "$JAIL/etc/localtime"

	# Generate .inputrc for jail users (optional):
	cat >"$JAIL/root/.inputrc" <<'EOF'
$include /etc/inputrc
# alternate mappings for "up" and "down" to search the history
"\e[A": history-search-backward
"\eOA": history-search-backward
"\e[B": history-search-forward
"\eOB": history-search-forward
EOF
	cp -pr "$JAIL/root/.inputrc" "$JAIL/etc/skel/.inputrc"

	# Create inmate user/group in jail:
	groupadd -R "$JAIL"            -g "$JUID" "$JUSR"
	useradd  -R "$JAIL" -u "$JUID" -g "$JUID" "$JUSR"

	# Create /etc/resolv.conf in jail:
	printf 'nameserver %s\n' "$JNET.1" >"$JAIL/etc/resolv.conf"

	# Mount /var/tmp/portage, /var/db/repos and /var/cache/distfiles:
	mount_jail_var "$JAIL" "$JNAM"

	# Set jail's locale:
	nsrun -impuCTn=/run/netns/ns0 -r="$JAIL" -P="LANG=C.UTF-8" \
		/usr/bin/eselect locale set C.UTF8

	# Emerge firefox/telegram in jail:
	case "z$7" in
	zfirefox*)
		nsrun -impuCTn=/run/netns/ns0 -r="$JAIL" -P="LANG=C.UTF-8" \
			/usr/bin/emerge -av www-client/firefox
		;;
	ztelegram*)
		nsrun -impuCTn=/run/netns/ns0 -r="$JAIL" -P="LANG=C.UTF-8" \
			/usr/bin/emerge -av net-im/telegram-desktop
		;;
	esac

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
	printf 'nameserver %s\n' "$JNET.1" >"$JAIL/etc/resolv.conf"

	# Mount /var/tmp/portage, /var/db/repos and /var/cache/distfiles:
	mount_jail_var "$JAIL" "$JNAM"

	# Do updates (emerge --update --deep --newuse @world):
	nsrun -impuCTn=/run/netns/ns0 -r="$JAIL" -P="LANG=C.UTF-8" \
		/usr/bin/emerge -vuDN @world

	# Umount /var/tmp/portage, /var/db/repos and /var/cache/distfiles:
	umount_jail_var "$JAIL" "$JNAM"
}

# USAGE: enter_jail path/to/jail JUSR JUID
enter_jail() {
	chdir_jail "$1"
	[ "z$JAIL" != "z" ] || die
	[ "z$JNAM" != "z" ] || die
	[ "z$JNET" != "z" ] || die
	JUSR="$2"
	JUID="$3"
	expr match "$JUSR" '[a-zA-Z_][a-zA-Z0-9_]*$' \
		|| die "invalid user name: $JUSR"
	expr match "$JUID" '[1-9][0-9]*$' \
		|| die "invalid uid: $JUID"

	# Update /etc/resolv.conf in jail:
	printf 'nameserver %s\n' "$JNET.1" >"$JAIL/etc/resolv.conf"

	# Transfer X11 MIT-MAGIC-COOKIE to JUSR:
	XDMAUTHD="/var/lib/xdm/authdir/authfiles/"
	XDMAUTHF="`ls -t "$XDMAUTHD" | head -n1`"
	MITMACOO="`xauth -f "$XDMAUTHD/$XDMAUTHF" list \
		| head -n1 | awk '{print $3}'`"
	true >"$JAIL/home/$JUSR/.Xauthority"
	xauth -f "$JAIL/home/$JUSR/.Xauthority" add "$JNET.1:0" . "$MITMACOO"
	chown "$JUID:$JUID" "$JAIL/home/$JUSR/.Xauthority"

	# Enter as JUSR:
	nsrun -impuCTn=/run/netns/ns0 -r="$JAIL" -P="LANG=C.UTF-8" \
		-P="DISPLAY=$JNET.1:0" \
		/bin/su -w DISPLAY -Pl "$JUSR"
}

case "z$2" in
z|zcreate|zfirefox|ztelegram*)
	mkjail "$1" "$ARCH" "$PROF" "$DSRV" "$JUSR" "$JUID" "$2"
	;;
zupdate)
	update_jail "$1"
	;;
zenter)
	enter_jail "$1" "$JUSR" "$JUID"
	;;
zroot)
	enter_jail "$1" root 0
	;;
z*)
	die "USAGE: $0 /path/to/jail {create|firefox|telegram|update|enter}"
	;;
esac

# vi:set ft=sh tw=79 sw=8 ts=8 noet:
