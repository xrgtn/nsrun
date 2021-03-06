# nsrun

## Intro

**nsrun** is a hybrid between
[nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
and
[unshare(1)](https://man7.org/linux/man-pages/man1/unshare.1.html)
from util-linux package. It runs given command (or login shell for user
account) in isolated environment: in other
[namespace[s]](https://man7.org/linux/man-pages/man7/namespaces.7.html)
and/or in
[chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html).
When switching to namespace, **nsrun** allows either entering existing
([setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html))
or creating
([unshare(2)](https://man7.org/linux/man-pages/man2/unshare.2.html))
a new one. When **nsrun** creates new namespace, it allows to bind-mount its ns
file to a specified location. Entering all namespaces of a running process (in
single call) is also supported, via `-t=PID` option.

When new *mount* namespace is *created* (along with others or alone) and
`-r=ROOT` option is specified, **nsrun** happily chooses to do
[pivot\_root(2)](https://man7.org/linux/man-pages/man2/pivot_root.2.html)
instead of *chroot(2)*. If you didn't know, *chroot(2)* changes root of a
process, while *pivot\_root(2)* changes root of a namespace (of a mount
namespace, to be exact). Main difference is, when you _enter_ namespace of
the chroot()-ed process from outside (via *setns()* call), your root
will remain outside the jail. When you enter pivot()-ed namespace, you end
up in jail all right.

## Goal

**nsrun** was created in attempt to simplify chore of executing `nsenter`,
`unshare`, `chroot`, `mount` & co when trying to run `firefox` or e.g.
`telegram-desktop` in isolated chroot jail (unable to eavesdrop on local
network traffic or tattle ethernet adapter's MAC address).

The goal at large was maximal possible isolation and anonymization when running
untrusted binaries without using a full-blown virtual machine. But **nsrun** is
only one tool - you would also need to:
1. prepare a ___separate filesystem___ for jail (beware of
   [inotify](https://man7.org/linux/man-pages/man7/inotify.7.html)
   and its ilk; JFYI `firefox` ___does___ use *inotify*);
2. set up minimal distro in jail, not just copy binaries and .so files
   they depend on (for Debian GNU/Linux, there used to exist some tools
   like `dchroot`, `schroot` et cetera, I think they still do;  
   for Gentoo I'm writing `mkgentoojail.sh` script).  
   If you wonder why copying executables with their depenedncies won't
   do, I tell you that even `glibc` may want to load `libnss_db.so` and co
   which are _not_ listed as `NEEDED` in `objdump --private-headers`.
   Of course, <strike>complex</strike>bloated software like `firefox` or
   `telegram` load plugins programmatically on a whim and they need _data_
   files you typically have no idea from where;
3. set up network namespace before (or after) *unshare(2)*. I recommend the
   former as it's easier to set up statically by `/etc/init.d/ns0`,
   `/etc/init.d/ns1` and so on and make them start _after_
   `/etc/init.d/iptables` and `/etc/init.d/ip6tables`, but _before_
   `/etc/init.d/tor`, with the latter having:
   ```
   SocksPort       192.168.0.1:9050
   TransPort       192.168.0.1:9051
   DNSPort         192.168.0.1:9053
   SocksPort       192.168.1.1:9050
   TransPort       192.168.1.1:9051
   DNSPort         192.168.1.1:9053
   ...
   ```
   already in place in `/etc/tor/torrc` (to use transparent redirection of all
   tcp and DNS traffic from jailed net namespaces to tor daemon in initial
   namespace, with all other traffic except ICMP silently dropped with extreme
   prejudice, even NTP and DHCP). With net namespace prepared beforehand,
   **nsrun** _enters_ it while _creating_ all other necessary namespaces.
4. create unprivileged user account in jail (with unassuming name like "user"
   or "foobar"), to run target binary;
5. currently, **nsrun** mounts fake data over /proc/bus/pci only (so that
   jailed `lspci` will return empty list of devices). If you need to fake
   /proc/cpuinfo or hide other parts, manual intervention is required inside
   the jail, before running the target;
6. security (and anonimity) is not a state, but a process. As more features are
   added to Linux kernel, you need to consider whether it's safe enough for you
   or better be disabled/plug-that-hole-d, on a case by case basis;
7. regarding the (6) above, I think that
   [user namespace](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
   feature is both insecure and not production-ready yet (in particular, I
   cannot make it work together with pivot\_root() with the cause unknown still),
   so I'd recommend disabling `CONFIG_USER_NS` alltogether (more data required
   to make a final decision on the matter).

## Examples

1. Run `/bin/ping` in separate
   [net namespace](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
   (prepared beforehand by `/bin/ip`):
   ```
   gentoo ~ # ip link add veth1 type veth peer name p-veth1
   gentoo ~ # ip address replace 192.168.1.1/24 dev veth1
   gentoo ~ # ip link set dev veth1 up
   gentoo ~ # ip netns add ns1
   gentoo ~ # ip link set dev p-veth1 netns ns1
   gentoo ~ # ip netns exec ns1 ip address replace 192.168.1.2/24 dev p-veth1
   gentoo ~ # ip netns exec ns1 ip link set dev p-veth1 up
   gentoo ~ # nsrun -n=/run/netns/ns1 /bin/ping 192.168.1.1 -c1
   nsrun: changed u:gid 0/0/0/32766:0/0/0/0 => 0:0
   nsrun: dropped 10 supplementary groups
   nsrun: executing /bin/ping
   PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
   64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.111 ms

   --- 192.168.1.1 ping statistics ---
   1 packets transmitted, 1 received, 0% packet loss, time 0ms
   rtt min/avg/max/mdev = 0.111/0.111/0.111/0.000 ms
   gentoo ~ # ip netns del ns1
   ```
2. run `ps` in new pid+mount namespace (when `CLONE_NEWNS` is unshare()-d,
   it's OK to mount proc filesystem directly over existing /proc in system
   root, prior chroot()/pivot\_root() is unnecessary):
   ```
   gentoo ~ # nsrun -pm /bin/ps aux
   nsrun: changed u:gid 0/0/0/32765:0/0/0/0 => 0:0
   nsrun: dropped 10 supplementary groups
   nsrun: mounted /proc, /proc/bus/pci, /proc/bus/pci/devices, /dev/pts, /dev/shm
   nsrun: executing /bin/ps
   USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
   root         1  0.0  0.0   3292  1016 ?        R+   15:44   0:00 /bin/ps aux
   ```
3. run `emerge -s %^jail` in `/jail0` with all namespaces (except user)
   switched:
   ```
   gentoo ~ # nsrun -impuCTn=/run/netns/ns0 -r=/jail0 -P="LANG=C.UTF-8" /usr/bin/emerge -s %^jail
   nsrun: changed u:gid 0/0/0/32766:0/0/0/0 => 0:0
   nsrun: dropped 10 supplementary groups
   nsrun: pivoted root to /jail0
   nsrun: mounted /proc, /proc/bus/pci, /proc/bus/pci/devices, /dev/mqueue, /dev/pts, /dev/shm
   nsrun: set hostname to "localhost"
   nsrun: executing /usr/bin/emerge
   
   [ Results for search key : %^jail ]
   Searching...
   
   *  app-misc/jail
         Latest version available: 2.0-r4
         Latest version installed: [ Not Installed ]
         Size of files: 31 KiB
         Homepage:      https://github.com/spiculator/jail
         Description:   Builds a chroot and configures all the required files, directories and libraries
         License:       GPL-2
   
   [ Applications found : 1 ]
   ```
