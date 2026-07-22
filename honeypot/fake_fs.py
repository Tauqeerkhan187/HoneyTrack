# Author : TK
# Date: 06-06-2026
# Purpose: fake filesystem for project

import re
from datetime import datetime, timedelta, timezone

FAKE_FILESYSTEM = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "srv", "tmp", "usr", "var"],
    "/etc": ["passwd", "shadow", "hostname", "hosts", "crontab", "ssh", "os-release"],
    "/root": [".bash_history", ".bashrc", ".ssh", "dead.letter"],
    "/root/.ssh": ["authorized_keys"],
    "/tmp": [],
    "/home": ["ubuntu"],
    "/proc": ["cpuinfo", "meminfo", "version"],
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
    "/root/.bash_history": "",   # Empty — attacker thinks they're first
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


def fake_uname():
    return "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"


def fake_whoami(user="root"):
    return user


def fake_id(user="root"):
    if user not in FAKE_USERS:
        return f"id: '{user}': no such user"
    uid, gid, name = FAKE_USERS[user]
    return f"uid={uid}({name}) gid={gid}({name}) groups={gid}({name})"

def _uptime_parts():
    delta = datetime.now(timezone.utc) - FAKE_BOOT_TIME
    hours, remainder = divmod(delta.seconds, 3600)
    return delta.days, hours, remainder // 60


def fake_uptime():
    days, hours, minutes = _uptime_parts()
    now = datetime.now().strftime("%H:%M:%S")
    return (f"{now} up {days} days, {hours}:{minutes:02d}, 1 user, "
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

def _env_for(cwd="/root", user="root"):
    env = dict(FAKE_ENV)
    env["PWD"] = cwd
    env["USER"] = user
    env["LOGNAME"] = user
    env["HOME"] = "/root" if user == "root" else f"/home/{user}"
    return env


def fake_env(cwd="/root", user="root"):
    return "\n".join(f"{k}={v}" for k, v in _env_for(cwd, user).items())


def expand_vars(text, cwd="/root", user="root"):
    """Expand $VAR and ${VAR} against the fake environment."""
    env = _env_for(cwd, user)

    def repl(match):
        return env.get(match.group(1) or match.group(2), "")

    return re.sub(r"\$\{(\w+)\}|\$(\w+)", repl, text)


def fake_ifconfig():
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255\n"
        "        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\n"
    )

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
    """Longest common prefix across a list of strings (for partial completion.)"""
    if not options:
        return ""
    prefix = options[0]
    for opt in options[1:]:
        while not opt.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix


def _complete_path(token: str, cwd: str, dirs_only: bool) -> tuple:
    """Complete a filesystem token against the fake FS.

    Returns (completion_suffix, matches)."""

    # Determine the directory to look in and the fragment being typed.
    if "/" in token:
        head, fragment = token.rsplit("/", 1)
        if token.startswith("/"):
            base_dir = head if head else "/"
        else:
            base_dir = _join(cwd, head) if head else cwd
    else:
        base_dir = cwd
        fragment = token

    entries = _list_dir(base_dir)
    matches = [e for e in entries if e.startswith(fragment)]

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

    common = common_prefix(matches)
    return common[len(fragment):], matches


def _join(base: str, name: str) -> str:
    """Join a base dir and a name into a normalized absolute-ish path."""
    if name.startswith("/"):
        return name.rstrip("/") or "/"
    base = base.rstrip("/")
    return f"{base}/{name}" if base else f"/{name}"


def complete(line: str, cwd: str) -> tuple:
    """Bash-like completion for the current input line.

    Returns (suffix, matches):
    . Suffix: text to insert at the cursor (may be empty)
    . matches: candidate list (for printing on ambiguous completion)
    """
    # See through a leading "sudo" (and "sudo -u user") so completion behaves
    # as if the wrapped command were typed directly.
    stripped = line
    while True:
        parts_check = stripped.split(" ", 1)
        if parts_check[0] == "sudo" and len(parts_check) == 2:
            remainder = parts_check[1]
            # skip "-u user" if present
            if remainder.startswith(("-u ", "--user ")):
                bits = remainder.split(" ", 2)
                remainder = bits[2] if len(bits) == 3 else ""
            stripped = remainder
        else:
            break

    # Completing the command name (first word, no space yet).
    if " " not in stripped:
        matches = [c for c in KNOWN_COMMANDS if c.startswith(stripped)]
        if not matches:
            return "", []
        if len(matches) == 1:
            return matches[0][len(stripped):] + " ", matches
        return _common_prefix(matches)[len(stripped):], matches

    # Completing an arg (a path)
    parts = stripped.split(" ")
    cmd = parts[0]
    token = parts[-1]
    dirs_only = cmd in _DIR_ONLY_COMMANDS
    return _complete_path(token, cwd, dirs_only)


