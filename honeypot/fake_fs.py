# Author : TK
# Date: 06-06-2026
# Purpose: fake filesystem for project

import re
from datetime import datetime, timedelta, timezone

FAKE_FILESYSTEM = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"],

    "/bin": ["bash", "cat", "chmod", "chown", "cp", "date", "dd", "df", "echo", "grep",
             "gzip", "hostname", "kill", "ln", "ls", "mkdir", "mv", "ping", "ps", "pwd",
             "rm", "sed", "sh", "sleep", "tar", "touch", "uname", "wget"],
    "/sbin": ["blkid", "fdisk", "fsck", "ifconfig", "init", "iptables", "mkfs", "reboot",
              "route", "shutdown", "sysctl"],
    "/boot": ["config-5.15.0-91-generic", "grub", "initrd.img-5.15.0-91-generic",
              "System.map-5.15.0-91-generic", "vmlinuz-5.15.0-91-generic"],
    "/dev": ["null", "zero", "random", "urandom", "sda", "sda1", "tty", "pts", "shm"],
    "/lib": ["modules", "systemd", "terminfo", "udev", "x86_64-linux-gnu"],
    "/opt": [],
    "/srv": [],
    "/sys": ["block", "class", "devices", "fs", "kernel", "module"],
    "/run": ["lock", "log", "sshd.pid", "systemd", "user", "utmp"],

    "/etc": ["apt", "cron.d", "cron.daily", "crontab", "default", "fstab", "group",
             "hostname", "hosts", "init.d", "issue", "logrotate.d", "motd", "network",
             "os-release", "passwd", "profile", "resolv.conf", "shadow", "ssh",
             "sudoers", "sysctl.conf", "systemd"],
    "/etc/ssh": ["moduli", "ssh_config", "ssh_config.d", "ssh_host_ecdsa_key",
                 "ssh_host_ecdsa_key.pub", "ssh_host_ed25519_key",
                 "ssh_host_ed25519_key.pub", "ssh_host_rsa_key",
                 "ssh_host_rsa_key.pub", "sshd_config", "sshd_config.d"],
    "/etc/cron.d": ["e2scrub_all"],
    "/etc/cron.daily": ["apt-compat", "dpkg", "logrotate", "man-db"],

    "/home": ["ubuntu"],
    "/home/ubuntu": [".bash_history", ".bash_logout", ".bashrc", ".cache", ".profile", ".ssh"],
    "/home/ubuntu/.ssh": ["authorized_keys", "known_hosts"],

    "/root": [".bash_history", ".bashrc", ".cache", ".profile", ".ssh", "dead.letter"],
    "/root/.ssh": ["authorized_keys", "known_hosts"],

    "/tmp": [],

    "/proc": ["1", "cpuinfo", "meminfo", "mounts", "net", "self", "stat", "uptime", "version"],

    "/usr": ["bin", "games", "include", "lib", "local", "sbin", "share", "src"],
    "/usr/bin": ["apt", "awk", "curl", "dpkg", "env", "free", "id", "last", "netstat",
                 "perl", "python3", "screen", "ss", "ssh", "sudo", "systemctl", "top",
                 "vim", "w", "wget", "whoami"],
    "/usr/local": ["bin", "etc", "games", "include", "lib", "sbin", "share", "src"],
    "/usr/local/bin": [],
    "/usr/sbin": ["cron", "sshd", "useradd", "userdel", "usermod", "visudo"],

    "/var": ["backups", "cache", "lib", "local", "lock", "log", "mail", "opt", "run",
             "spool", "tmp"],
    "/var/log": ["alternatives.log", "apt", "auth.log", "btmp", "dpkg.log", "journal",
                 "kern.log", "lastlog", "syslog", "wtmp"],
    "/var/spool": ["cron", "mail"],
    "/var/spool/cron": ["crontabs"],
    "/var/spool/cron/crontabs": [],
    "/var/www": [],
    "/var/tmp": [],
}

FAKE_FILE_CONTENTS = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
    ),
    "/etc/hostname": "ubuntu-server\n",
    "/etc/os-release": (
        'NAME="Ubuntu"\n'
        'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\n'
        'VERSION_ID="22.04"\n'
    ),
    "/proc/version": (
        "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-032) "
        "(gcc version 11.4.0) #101-Ubuntu SMP\n"
    ),
    "/proc/cpuinfo": (
        "processor\t: 0\nvendor_id\t: GenuineIntel\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz\n"
        "cpu cores\t: 1\n"
    ),
    "/root/.bash_history": "",   # Empty - attacker thinks they're first
    "/etc/shadow": "Permission denied\n",
}

# Fixed fake boot time so uptime stays consistent across commands
# (w, uptime, last) and grows realistically during a session.
FAKE_BOOT_TIME = datetime.now(timezone.utc) - timedelta(days=12, hours=3, minutes=41)

FAKE_USERS = {
    "root":   (0, 0, "root"),
    "daemon": (1, 1, "daemon"),
    "ubuntu": (1000, 1000, "ubuntu"),
}

FAKE_ENV = {
    "SHELL": "/bin/bash",
    "PWD": "/root",
    "LOGNAME": "root",
    "HOME": "/root",
    "LANG": "en_US.UTF-8",
    "TERM": "xterm-256color",
    "USER": "root",
    "SHLVL": "1",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "MAIL": "/var/mail/root",
    "_": "/usr/bin/env",
}


# filesystem


def fake_ls(path="/"):
    """Return a fake directory listing for a given path."""
    path = path.rstrip("/") or "/"
    contents = FAKE_FILESYSTEM.get(path, None)
    if contents is None:
        return f"ls: cannot access '{path}': No such file or directory"
    if not contents:
        return ""
    return "  ".join(contents)


def fake_cat(path):
    """Return fake file contents for a given path."""
    content = FAKE_FILE_CONTENTS.get(path, None)
    if content is None:
        return f"cat: {path}: No such file or directory"
    return content


def fake_pwd(cwd="/root"):
    return cwd


#  identity


def fake_uname():
    return "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"


def fake_whoami(user="root"):
    return user


def fake_id(user="root"):
    if user not in FAKE_USERS:
        return f"id: '{user}': no such user"
    uid, gid, name = FAKE_USERS[user]
    return f"uid={uid}({name}) gid={gid}({name}) groups={gid}({name})"


def fake_ifconfig():
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255\n"
        "        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\n"
    )


# recon


def _uptime_parts():
    delta = datetime.now(timezone.utc) - FAKE_BOOT_TIME
    hours, remainder = divmod(delta.seconds, 3600)
    return delta.days, hours, remainder // 60


def fake_uptime():
    days, hours, minutes = _uptime_parts()
    now = datetime.now().strftime("%H:%M:%S")
    return (f" {now} up {days} days, {hours}:{minutes:02d},  1 user,  "
            f"load average: 0.08, 0.03, 0.01")


def fake_ps(args=None):
    flat = " ".join(args or [])

    if "aux" in flat or "-ef" in flat or "-e" in flat:
        return (
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root           1  0.0  0.1 168404 11876 ?        Ss   Jun15   0:04 /sbin/init\n"
            "root           2  0.0  0.0      0     0 ?        S    Jun15   0:00 [kthreadd]\n"
            "root           3  0.0  0.0      0     0 ?        I<   Jun15   0:00 [rcu_gp]\n"
            "root         412  0.0  0.2  47156 16924 ?        S<s  Jun15   0:03 /lib/systemd/systemd-journald\n"
            "root         441  0.0  0.1  21484  5628 ?        Ss   Jun15   0:00 /lib/systemd/systemd-udevd\n"
            "systemd+     618  0.0  0.1  16104  6844 ?        Ss   Jun15   0:01 /lib/systemd/systemd-resolved\n"
            "root         702  0.0  0.1  12180  6852 ?        Ss   Jun15   0:00 /usr/sbin/cron -f\n"
            "message+     704  0.0  0.1   8892  4436 ?        Ss   Jun15   0:02 /usr/bin/dbus-daemon --system\n"
            "root         731  0.0  0.2  15420  9160 ?        Ss   Jun15   0:00 /usr/sbin/sshd -D\n"
            "root        1109  0.0  0.1   8356  3568 ?        Ss   Jun15   0:00 /usr/sbin/atd -f\n"
            "root        1842  0.0  0.1   9204  5124 pts/0    Ss   09:22   0:00 -bash\n"
            "root        1889  0.0  0.0  10084  3272 pts/0    R+   09:24   0:00 ps aux"
        )

    return ("    PID TTY          TIME CMD\n"
            "   1842 pts/0    00:00:00 bash\n"
            "   1889 pts/0    00:00:00 ps")


def fake_netstat(args=None):
    # NOTE: never expose ports 2222/2323 or a python process here - that
    # would immediately give away the honeypot. PIDs match fake_ps output.
    return (
        "Active Internet connections (only servers)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      731/sshd: /usr/sbin\n"
        "tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      618/systemd-resolve\n"
        "tcp6       0      0 :::22                   :::*                    LISTEN      731/sshd: /usr/sbin\n"
        "udp        0      0 127.0.0.53:53           0.0.0.0:*                           618/systemd-resolve\n"
        "udp        0      0 0.0.0.0:68              0.0.0.0:*                           542/dhclient"
    )


def fake_ss(args=None):
    return (
        "Netid  State   Recv-Q  Send-Q   Local Address:Port     Peer Address:Port  Process\n"
        "udp    UNCONN  0       0        127.0.0.53%lo:53             0.0.0.0:*      users:((\"systemd-resolve\",pid=618,fd=12))\n"
        "udp    UNCONN  0       0              0.0.0.0:68            0.0.0.0:*      users:((\"dhclient\",pid=542,fd=6))\n"
        "tcp    LISTEN  0       128            0.0.0.0:22            0.0.0.0:*      users:((\"sshd\",pid=731,fd=3))\n"
        "tcp    LISTEN  0       128               [::]:22               [::]:*      users:((\"sshd\",pid=731,fd=4))"
    )


def fake_w(peer_ip="10.0.0.14"):
    days, hours, minutes = _uptime_parts()
    now = datetime.now().strftime("%H:%M:%S")
    return (
        f" {now} up {days} days, {hours}:{minutes:02d},  1 user,  load average: 0.08, 0.03, 0.01\n"
        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        f"root     pts/0    {peer_ip:<15}  {now[:5]}    0.00s  0.03s  0.00s -bash"
    )


def fake_who(peer_ip="10.0.0.14"):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"root     pts/0        {stamp} ({peer_ip})"


def fake_last(peer_ip="10.0.0.14"):
    now = datetime.now().strftime("%a %b %d %H:%M")
    return (
        f"root     pts/0        {peer_ip:<15}  {now}   still logged in\n"
        "root     pts/0        10.0.0.14        Mon Jun 15 09:22 - 10:41  (01:19)\n"
        "root     pts/0        10.0.0.14        Sun Jun 14 18:03 - 18:44  (00:41)\n"
        "reboot   system boot  5.15.0-91-generi Sun Jun 14 09:14   still running\n"
        "\nwtmp begins Sun Jun 14 09:14:22 2026"
    )


def fake_free(args=None):
    if "-h" in " ".join(args or []):
        return (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:           3.8Gi       412Mi       2.9Gi       1.0Mi       528Mi       3.2Gi\n"
            "Swap:          2.0Gi          0B       2.0Gi"
        )
    return (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:         4014172      421836     3050112        1024      542224     3358908\n"
        "Swap:        2097148           0     2097148"
    )


def fake_df(args=None):
    if "-h" in " ".join(args or []):
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        49G  8.2G   38G  18% /\n"
            "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
            "tmpfs           392M  1.1M  391M   1% /run"
        )
    return (
        "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
        "/dev/sda1       51343840 8598432  39923216  18% /\n"
        "tmpfs            2007084       0   2007084   0% /dev/shm\n"
        "tmpfs             401420    1104    400316   1% /run"
    )


# environment


def _env_for(cwd="/root", user="root"):
    env = dict(FAKE_ENV)
    home = "/root" if user == "root" else f"/home/{user}"
    env["PWD"] = cwd
    env["USER"] = user
    env["LOGNAME"] = user
    env["HOME"] = home
    env["MAIL"] = f"/var/mail/{user}"
    return env


def fake_env(cwd="/root", user="root"):
    return "\n".join(f"{k}={v}" for k, v in _env_for(cwd, user).items())


def expand_vars(text, cwd="/root", user="root"):
    """Expand $VAR and ${VAR} against the fake environment."""
    env = _env_for(cwd, user)

    def repl(match):
        return env.get(match.group(1) or match.group(2), "")

    return re.sub(r"\$\{(\w+)\}|\$(\w+)", repl, text)


#  completion


KNOWN_COMMANDS = [
    "ls", "cat", "cd", "pwd", "whoami", "id", "uname", "ifconfig", "ip",
    "wget", "curl", "python", "python3", "perl", "bash", "sh",
    "chmod", "chown", "chattr", "crontab", "touch", "echo",
    "clear", "reset", "exit", "logout", "history", "sudo",
    "ps", "netstat", "ss", "w", "who", "last", "uptime",
    "env", "printenv", "free", "df",
]

_DIR_ONLY_COMMANDS = {"cd"}


def _is_dir(path: str) -> bool:
    """A path is a directory if it's a key in FAKE_FILESYSTEM."""
    return path.rstrip("/") in FAKE_FILESYSTEM or path == "/"


def _list_dir(path: str) -> list:
    """Return entries in a fake directory, or [] if it isn't one."""
    return FAKE_FILESYSTEM.get(path.rstrip("/") or "/", [])


def _common_prefix(options: list) -> str:
    """Longest common prefix across a list of strings (for partial completion)."""
    if not options:
        return ""
    prefix = options[0]
    for opt in options[1:]:
        while not opt.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix


def _join(base: str, name: str) -> str:
    """Join a base dir and a name into a normalized absolute-ish path."""
    if name.startswith("/"):
        return name.rstrip("/") or "/"
    base = base.rstrip("/")
    return f"{base}/{name}" if base else f"/{name}"


def _finish(matches: list, fragment: str, add_space: bool = False) -> tuple:
    """Turn a list of candidates into a (suffix, matches) completion result."""
    if not matches:
        return "", []

    if len(matches) == 1:
        suffix = matches[0][len(fragment):]
        return (suffix + " ") if add_space else suffix, matches

    return _common_prefix(matches)[len(fragment):], matches


def _complete_path(token: str, cwd: str, dirs_only: bool) -> tuple:
    """Complete a filesystem token against the fake FS.

    Returns (completion_suffix, matches).
    """
    # Split the token into the directory to search and the fragment typed.
    if "/" in token:
        head, fragment = token.rsplit("/", 1)
        if token.startswith("/"):
            base_dir = head if head else "/"
        else:
            base_dir = _join(cwd, head) if head else cwd
    else:
        base_dir = cwd
        fragment = token

    matches = [e for e in _list_dir(base_dir) if e.startswith(fragment)]

    if dirs_only:
        matches = [e for e in matches if _is_dir(_join(base_dir, e))]

    if not matches:
        return "", []

    if len(matches) == 1:
        completed = matches[0]
        suffix = completed[len(fragment):]
        if _is_dir(_join(base_dir, completed)):
            suffix += "/"
        return suffix, matches

    return _common_prefix(matches)[len(fragment):], matches


def complete(line: str, cwd: str) -> tuple:
    """Bash-like completion for the current input line.

    Returns (suffix, matches):
      - suffix: text to insert at the cursor (may be empty)
      - matches: candidate list

    Sees through a leading "sudo" (and "sudo -u <user>") so completion
    behaves as if the wrapped command were typed directly. While the
    username after -u is still being typed, usernames are completed
    instead of commands.
    """
    tokens = line.split()

    # A trailing space means a new, empty token is being started.
    if line.endswith(" ") or not tokens:
        tokens.append("")

    index = 0
    while index < len(tokens) and tokens[index] == "sudo":
        index += 1

        if index < len(tokens) and tokens[index] in ("-u", "--user"):
            # Still typing the username itself -> complete usernames.
            if index + 1 == len(tokens) - 1:
                return _finish(
                    [u for u in FAKE_USERS if u.startswith(tokens[-1])],
                    tokens[-1],
                    add_space=True,
                )

            if index + 1 >= len(tokens):
                break

            index += 2

    rest = tokens[index:] or [""]
    fragment = rest[-1]

    # First token -> command name completion.
    if len(rest) == 1:
        return _finish(
            [c for c in KNOWN_COMMANDS if c.startswith(fragment)],
            fragment,
            add_space=True,
        )

    # Later tokens -> path completion.
    return _complete_path(fragment, cwd, rest[0] in _DIR_ONLY_COMMANDS)

