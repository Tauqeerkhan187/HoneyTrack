# Author: TK
# Date: 06-06-2026
# Purpose: Config for project

import os

# -- Honeypot --
HONEYPOT_HOST = "0.0.0.0"
HONEYPOT_PORT = 2222      # Listen on 2222 (no root needed), forward from 22 later
HONEYPOT_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
FAKE_HOSTNAME = "ubuntu-server"
FAKE_USER = "root"
FAKE_IFACE = "eth0"
FAKE_IP = "192.168.56.110"
FAKE_NETMASK = "255.255.255.0"
FAKE_BROADCAST = "192.168.56.255"
FAKE_CIDR = "192.168.56.0/24"
FAKE_GATEWAY = "192.168.56.1"
FAKE_MAC = "08:00:27:ab:cd:ef"
FAKE_MAC6 = "fe80::a00:27ff:feab:cdef"
# Telnet Honeypot
TELNET_HOST = "0.0.0.0"
TELNET_PORT = 2323 # 2323 avoids needing root; forward 23 -> 2323 for real :23


# -- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "data", "logs")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
ATTACK_PATTERNS_FILE = os.path.join(BASE_DIR, "data", "attack_patterns.json")

# API keys
try:
    from config_local import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
except ImportError:
    ABUSEIPDB_API_KEY = ""
    VIRUSTOTAL_API_KEY = ""

# Dashboard
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
DEBUG = True

# --- Session ---
MAX_SESSION_DURATION = 300 # seconds before auto-disconnect
FAKE_AUTH_DELAY = 1.5      # seconds to simulate real auth check


