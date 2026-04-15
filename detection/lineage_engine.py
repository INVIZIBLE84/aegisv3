# detection/lineage_engine.py
"""
Process Lineage Engine - Aegis-LX
===================================
Detects suspicious parent-child process relationships.

Uses /proc/<pid>/status to read PPid — no eBPF needed.
This works on every Linux kernel without any tracepoint issues.

WHAT IT CATCHES:
  nginx -> bash       = RCE (web server spawned a shell)
  postgres -> whoami  = RCE (database spawned recon)
  python3 -> bash     = suspicious script spawning shell
  java -> nc          = likely webshell or exploit

HOW IT WORKS:
  Every exec event already has a PID.
  We read /proc/<pid>/status to get the parent PID (PPid field).
  We resolve the parent name from /proc/<ppid>/comm.
  Then we check if this parent-child combination is suspicious.
"""

import os
import re as _re

# Aegis own PID — never flag ourselves
AEGIS_PID = os.getpid()

# ── Processes that should never spawn shells or attack tools ─────────────────
SUSPICIOUS_PARENTS = {
    "nginx", "apache2", "apache", "httpd", "lighttpd", "caddy",
    "tomcat", "java", "php", "php-fpm", "php8",
    "gunicorn", "uwsgi", "passenger",
    "postgres", "mysqld", "mongod", "redis-server", "mariadb",
    "named", "bind", "vsftpd", "proftpd", "dovecot",
    "postfix", "sendmail", "exim4",
    "python3", "python", "python2",
    "perl", "ruby", "lua", "node", "nodejs",
}

SHELL_PROCESSES = {
    "bash", "sh", "zsh", "dash", "ksh", "fish",
    "tcsh", "ash", "rbash", "busybox",
}

ATTACK_PROCESSES = {
    "nc", "ncat", "netcat", "nmap", "curl", "wget",
    "id", "whoami", "uname", "ifconfig",
    "cat", "tac", "find", "env", "printenv",
    "ps", "ss", "netstat", "lsof",
    "chmod", "chown", "crontab",
    "gcc", "cc", "g++", "make",
}

TRUSTED_PAIRS = {
    ("sshd","bash"),("sshd","sh"),("sshd","zsh"),
    ("login","bash"),("login","sh"),("login","zsh"),
    ("sudo","bash"),("su","bash"),
    ("cron","bash"),("cron","sh"),
    ("systemd","bash"),("systemd","sh"),
    ("bash","bash"),("bash","sh"),
    ("sh","sh"),("sh","bash"),
    ("zsh","bash"),("tmux","bash"),("screen","bash"),
    ("gnome-terminal","bash"),("xterm","bash"),
}



class LineageEngine:
    def __init__(self):
        self.tainted = {}     # pid -> reason
        self.MAX_TAINTED = 500

    def analyze(self, exec_events):
        alerts = []

        for ev in exec_events:
            pid   = ev.get("pid")
            ppid  = ev.get("ppid")
            child = ev.get("process_name", "unknown")

            if not pid:
                continue

            # Skip Aegis itself
            if pid == AEGIS_PID or ppid == AEGIS_PID:
                continue

            # Use parent_comm resolved at event time (not /proc which may be stale)
            parent = ev.get("parent_comm", "unknown")
            if not parent or parent == "unknown":
                continue

            # Skip trusted pairs
            if (parent, child) in TRUSTED_PAIRS:
                continue

            # Check 1: suspicious parent spawning shell = RCE
            if parent in SUSPICIOUS_PARENTS and child in SHELL_PROCESSES:
                reason = parent + " spawned shell " + child + " -- likely RCE"
                self._taint(pid, reason)
                alerts.append(self._alert(ppid, parent, pid, child, ev,
                                          "EXECUTION", 4, reason))
                continue

            # Check 2: suspicious parent spawning attack tool
            if parent in SUSPICIOUS_PARENTS and child in ATTACK_PROCESSES:
                reason = parent + " spawned " + child + " -- suspicious"
                self._taint(pid, reason)
                alerts.append(self._alert(ppid, parent, pid, child, ev,
                                          "EXECUTION", 3, reason))
                continue

            # Check 3: tainted parent chain
            if ppid in self.tainted and child in (SHELL_PROCESSES | ATTACK_PROCESSES):
                reason = "tainted chain: " + parent + " -> " + child
                self._taint(pid, reason)
                alerts.append(self._alert(ppid, parent, pid, child, ev,
                                          "EXECUTION", 3, reason))

        return alerts

    def _alert(self, ppid, parent, pid, child, ev, phase, tier, detail):
        return {
            "source":      "LINEAGE",
            "parent_pid":  ppid,
            "parent_name": parent,
            "child_pid":   pid,
            "child_name":  child,
            "full_cmd":    ev.get("full_cmd", child),
            "phase":       phase,
            "tier":        tier,
            "mitre":       "T1059 (Command Execution via " + parent + ")",
            "detail":      detail,
            "timestamp":   ev.get("timestamp", ""),
        }

    def _taint(self, pid, reason):
        if pid is None:
            return
        if len(self.tainted) >= self.MAX_TAINTED:
            keys = list(self.tainted.keys())[:100]
            for k in keys:
                del self.tainted[k]
        self.tainted[pid] = reason
