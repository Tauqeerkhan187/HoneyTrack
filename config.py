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


