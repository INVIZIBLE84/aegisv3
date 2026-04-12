# detection/fim_engine.py
"""
File Integrity Monitor Engine - Aegis-LX
==========================================
Watches WHAT files are being opened, not WHO opened them.

This kills the LOLBin problem entirely:
  tac /etc/shadow    -> caught (openat hook sees /etc/shadow)
  strings /etc/shadow -> caught
  vim /etc/shadow    -> caught
  python3 -c "open('/etc/shadow')" -> caught
  ANY tool reading a sensitive file -> caught

HOW IT WORKS:
  The eBPF openat hook sends every file open event to Python.
  This engine checks if the opened filename matches our sensitive
  file watchlist. If it does, and the process is not on the
  trusted whitelist, it raises an alert with the appropriate
  kill chain phase and tier recommendation.
"""

# ── Sensitive file watchlist ──────────────────────────────────────────────────
# Any process opening these files (that is not whitelisted) triggers an alert.
# Key   = exact path or path prefix to match
# Value = dict with phase, tier, and mitre tag

SENSITIVE_FILES = {
    # Credential files
    "/etc/shadow":              {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1003.008 (/etc/shadow Access)"},
    "/etc/gshadow":             {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1003.008 (/etc/gshadow Access)"},
    "/etc/sudoers":             {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1548.003 (Sudoers Access)"},
    "/etc/sudoers.d":           {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1548.003 (Sudoers Dir Access)"},

    # User account info
    "/etc/passwd":              {"phase": "DISCOVERY",   "tier": 2, "mitre": "T1003.008 (Passwd Access)"},
    "/etc/group":               {"phase": "DISCOVERY",   "tier": 1, "mitre": "T1069 (Group Discovery)"},

    # SSH keys and config
    "/.ssh/id_rsa":             {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1552.004 (SSH Private Key)"},
    "/.ssh/id_ed25519":         {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1552.004 (SSH Private Key)"},
    "/.ssh/id_ecdsa":           {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1552.004 (SSH Private Key)"},
    "/.ssh/authorized_keys":    {"phase": "PERSISTENCE", "tier": 3, "mitre": "T1098.004 (Authorized Keys)"},
    "/.ssh/known_hosts":        {"phase": "DISCOVERY",   "tier": 1, "mitre": "T1018 (Remote System Discovery)"},

    # Shell history - attackers read this for credentials and patterns
    "/.bash_history":           {"phase": "DISCOVERY",   "tier": 2, "mitre": "T1552.003 (Bash History)"},
    "/.zsh_history":            {"phase": "DISCOVERY",   "tier": 2, "mitre": "T1552.003 (Zsh History)"},

    # Persistence targets
    "/.bashrc":                 {"phase": "PERSISTENCE", "tier": 2, "mitre": "T1546.004 (Bash Profile)"},
    "/.bash_profile":           {"phase": "PERSISTENCE", "tier": 2, "mitre": "T1546.004 (Bash Profile)"},
    "/etc/crontab":             {"phase": "PERSISTENCE", "tier": 3, "mitre": "T1053.003 (Cron Persistence)"},
    "/etc/cron.d":              {"phase": "PERSISTENCE", "tier": 3, "mitre": "T1053.003 (Cron Dir Access)"},
    "/etc/profile":             {"phase": "PERSISTENCE", "tier": 2, "mitre": "T1546.004 (Profile Persistence)"},
    "/etc/profile.d":           {"phase": "PERSISTENCE", "tier": 2, "mitre": "T1546.004 (Profile.d Access)"},

    # Cloud credentials
    "/.aws/credentials":        {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1552.001 (Cloud Credentials)"},
    "/.aws/config":             {"phase": "CREDENTIAL",  "tier": 2, "mitre": "T1552.001 (Cloud Config)"},
    "/.config/gcloud":          {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1552.001 (GCloud Credentials)"},
}

# ── Trusted processes that legitimately access these files ────────────────────
# These will NEVER trigger an alert even when opening sensitive files.
# sshd needs to read authorized_keys. passwd needs to read shadow. Etc.

TRUSTED_PROCESSES = {
    "sshd", "login", "passwd", "su", "sudo", "PAM",
    "systemd", "systemd-logind", "cron", "crond",
    "useradd", "usermod", "userdel", "groupadd",
    "chpasswd", "chage", "newgrp",
    "polkit", "polkitd",
    "aegis",        # never flag ourselves
    "python3",      # aegis runs as python3
    "python",
}


class FIMEngine:
    """
    File Integrity Monitor.
    Call analyze(file_events) every cycle with events from collect_file_events().
    Returns a list of FIM alerts.
    """

    def analyze(self, file_events):
        """
        file_events: list of dicts from collect_file_events()
        Returns: list of alert dicts (empty if nothing suspicious)
        """
        alerts = []

        for event in file_events:
            proc     = event.get("process_name", "unknown")
            filename = event.get("filename", "")
            pid      = event.get("pid")
            ts       = event.get("timestamp", "")

            # Skip trusted processes entirely
            if proc in TRUSTED_PROCESSES:
                continue

            # Check if this filename matches any sensitive path
            match = self._match_sensitive(filename)
            if match is None:
                continue

            rule = SENSITIVE_FILES[match]

            alerts.append({
                "source":    "FIM",
                "process":   proc,
                "pid":       pid,
                "filename":  filename,
                "matched":   match,
                "phase":     rule["phase"],
                "tier":      rule["tier"],
                "mitre":     rule["mitre"],
                "timestamp": ts,
                "detail":    proc + " opened " + filename + " [" + rule["mitre"] + "]",
            })

        return alerts

    def _match_sensitive(self, filename):
        """
        Returns the matching watchlist key if filename is sensitive.
        Supports both exact match and suffix match (for home-dir paths).
        Returns None if not sensitive.
        """
        if not filename:
            return None

        # Exact match first
        if filename in SENSITIVE_FILES:
            return filename

        # Suffix match — handles /home/user/.ssh/id_rsa, /root/.ssh/id_rsa etc.
        for pattern in SENSITIVE_FILES:
            if filename.endswith(pattern):
                return pattern

        return None
