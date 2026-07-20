# Author : TK
# Date: 06-06-2026
# Purpose: fake filesystem for project

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


def fake_whoami():
    return "root"


def fake_id():
    return "uid=0(root) gid=0(root) groups=0(root)"


def fake_ifconfig():
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255\n"
        "        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\n"
    )

KNOWN_COMMANDS = [
    "ls", "cat", "cd", "pwd", "whoami", "id", "uname", "ifconfig", "ip",
    "wget", "curl", "python", "python3", "perl", "bash", "sh", "chmod",
    "chown", "chattr", "crontab", "touch", "echo", "clear", "reset", "exit",
    "logout", "history",
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
    prefix = option[0]
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
    matches = [e or e in entries if e.startswith(fragment)]

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
    # Completing the command name (first word)
    if " " not in line:
        matches = [c for c in KNOWN_COMMANDS if c.startswith(line)]
        if not matches:
            return "", []
        if len(matches) == 1:
            return matches[0][len(line):] + " ", matches
        return _common_prefix(matches)[len(line):], matches

    # Completing an arg (a path).
    parts = line.split(" ")
    cmd = parts[0]
    token = parts[-1]
    dirs_only = cmd in _DIR_ONLY_COMMANDS
    return _complete_path(token, cwd, dirs_only)




