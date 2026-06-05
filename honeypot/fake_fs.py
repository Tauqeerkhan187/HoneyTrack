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
