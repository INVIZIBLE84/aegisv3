# detection/lineage_engine.py
"""
Process Lineage Engine - Aegis-LX
===================================
Tracks parent-child process relationships to detect RCE and
privilege abuse — regardless of what tool the attacker uses.

THE CORE INSIGHT:
  A command's danger depends heavily on WHO spawned it.

  SAFE:   bash -> ls          (admin typed ls in terminal)
  SAFE:   sshd -> bash        (admin logged in via SSH)
  DANGER: nginx -> bash       (web server spawned a shell = RCE)
  DANGER: postgres -> whoami  (database spawned recon = RCE)
  DANGER: python3 -> nc       (script opened reverse shell)
  DANGER: apache2 -> curl     (web process calling out = likely webshell)

HOW IT WORKS:
  1. Fork hook feeds parent->child PID pairs into a lineage map
  2. Exec hook provides ppid in each execution event
  3. Every execution is evaluated: is this parent allowed to spawn this child?
  4. Suspicious combinations → alert with phase + tier

This catches attacks that bypass both dictionary AND file watchlist:
  - Custom compiled binaries
  - Python/Perl one-liners used as shells
  - Any LOLBin spawned from an unexpected parent
"""

# ── Processes that should NEVER spawn interactive shells or recon tools ───────
# These are services. If they spawn a shell, something is very wrong.
# Aegis's own PID — loaded at runtime so we never flag ourselves
import os as _os
AEGIS_PID = _os.getpid()

SUSPICIOUS_PARENTS = {
    # Web servers
    "nginx", "apache2", "apache", "httpd", "lighttpd", "caddy",
    # Application servers
    "tomcat", "java", "node", "ruby", "php", "php-fpm", "php8",
    "gunicorn", "uwsgi", "passenger",
    # Databases
    "postgres", "mysqld", "mongod", "redis-server", "mariadb",
    # Other services that should never shell out
    "named", "bind", "vsftpd", "proftpd", "dovecot", "postfix",
    "sendmail", "exim4", "cups", "cupsd",
    # Scripting interpreters — spawning a shell from these = suspicious
    # (Aegis itself is excluded by PID check, not by name)
    "python3", "python", "python2",
    "perl", "ruby", "lua",
    "node", "nodejs",
}

# ── Shell processes — dangerous when spawned by a service ────────────────────
SHELL_PROCESSES = {
    "bash", "sh", "zsh", "dash", "ksh", "fish", "tcsh",
    "ash", "rbash", "busybox",
}

# ── Recon/attack tools — dangerous when spawned by a service ─────────────────
ATTACK_PROCESSES = {
    "nc", "ncat", "netcat", "nmap", "curl", "wget",
    "python", "python3", "perl", "ruby", "php",
    "id", "whoami", "uname", "ifconfig", "ip",
    "cat", "tac", "less", "more", "head", "tail",
    "find", "locate", "which", "env", "printenv",
    "ps", "top", "ss", "netstat", "lsof",
    "chmod", "chown", "chattr", "passwd",
    "crontab", "at", "wall",
    "gcc", "cc", "g++", "make",   # compiling on a prod server = suspicious
}

# ── Trusted parent-child pairs — always safe ─────────────────────────────────
# Format: (parent, child) — these combinations are explicitly whitelisted
TRUSTED_PAIRS = {
    ("sshd",    "bash"),
    ("sshd",    "sh"),
    ("sshd",    "zsh"),
    ("login",   "bash"),
    ("login",   "sh"),
    ("login",   "zsh"),
    ("sudo",    "bash"),
    ("su",      "bash"),
    ("cron",    "bash"),
    ("cron",    "sh"),
    ("systemd", "bash"),
    ("systemd", "sh"),
    ("bash",    "bash"),    # shell spawning subshell
    ("bash",    "sh"),
    ("sh",      "sh"),
    ("sh",      "bash"),
    ("zsh",     "bash"),
    ("tmux",    "bash"),
    ("screen",  "bash"),
    ("xterm",   "bash"),
    ("gnome-terminal", "bash"),
}

# Severity of the finding based on what combination was detected
def _classify(parent, child, parent_pid=None):
    """
    Returns (phase, tier, description) or None if not suspicious.
    parent_pid: if provided, skip if this is Aegis's own PID.
    """
    # Never flag Aegis's own python3 process
    if parent_pid is not None and parent_pid == AEGIS_PID:
        return None

    # Scripting interpreter or service spawning a shell = RCE
    if parent in SUSPICIOUS_PARENTS and child in SHELL_PROCESSES:
        return (
            "EXECUTION",
            4,
            parent + " spawned shell " + child + " -- likely RCE"
        )

    # Scripting interpreter or service spawning an attack tool
    if parent in SUSPICIOUS_PARENTS and child in ATTACK_PROCESSES:
        return (
            "EXECUTION",
            3,
            parent + " spawned " + child + " -- suspicious behaviour"
        )

    return None


class LineageEngine:
    """
    Tracks process parent-child relationships and flags suspicious spawn chains.

    Handles multi-hop chains:
      python3 -> sh -> bash -> whoami
    Once a suspicious parent spawns anything, its children are "tainted" —
    tracked in a tainted_pids set so the chain is followed.
    """

    def __init__(self):
        self.pid_map     = {}   # pid -> process_name
        self.tainted     = {}   # pid -> reason (why this pid is tainted)
        self.MAX_PIDS    = 2000
        self.MAX_TAINTED = 500

    def ingest_fork(self, fork_events):
        """Feed fork events — propagate taint to children."""
        for ev in fork_events:
            ppid  = ev.get("parent_pid")
            cpid  = ev.get("child_pid")
            pname = ev.get("parent_comm", "")
            self._register(ppid, pname)
            # If parent is tainted, child inherits taint
            if ppid in self.tainted:
                self._taint(cpid, "child of tainted PID " + str(ppid) +
                            " (" + self.tainted[ppid] + ")")

    def analyze(self, exec_events):
        """
        Check each execution for suspicious parent-child combinations.
        Also flags any exec by a tainted process.
        Returns list of lineage alert dicts.
        """
        alerts = []

        for ev in exec_events:
            pid   = ev.get("pid")
            ppid  = ev.get("ppid")
            child = ev.get("process_name", "unknown")

            self._register(pid, child)

            if not ppid:
                continue

            parent = self.pid_map.get(ppid, "unknown")

            # ── Check 1: direct suspicious parent-child ───────────────────
            if parent != "unknown" and (parent, child) not in TRUSTED_PAIRS:
                result = _classify(parent, child, parent_pid=ppid)
                if result:
                    phase, tier, description = result
                    # Taint this pid so its children are also tracked
                    self._taint(pid, description)
                    alerts.append(self._make_alert(
                        ppid, parent, pid, child, ev, phase, tier, description))
                    continue

            # ── Check 2: tainted parent executing anything notable ─────────
            if ppid in self.tainted and child in (SHELL_PROCESSES | ATTACK_PROCESSES):
                reason = self.tainted[ppid]
                description = "tainted chain: " + child + " spawned from " + parent + " (" + reason + ")"
                self._taint(pid, description)
                alerts.append(self._make_alert(
                    ppid, parent, pid, child, ev,
                    "EXECUTION", 3, description))

        return alerts

    def _make_alert(self, ppid, parent, pid, child, ev, phase, tier, description):
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
            "detail":      description,
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

    def _register(self, pid, name):
        if pid is None or not name:
            return
        if len(self.pid_map) >= self.MAX_PIDS:
            keys = list(self.pid_map.keys())[:200]
            for k in keys:
                del self.pid_map[k]
        self.pid_map[pid] = name
