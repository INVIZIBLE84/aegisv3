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
def _classify(parent, child):
    """
    Returns (phase, tier, description) or None if not suspicious.
    """
    # Service spawning a shell = almost certainly RCE
    if parent in SUSPICIOUS_PARENTS and child in SHELL_PROCESSES:
        return (
            "EXECUTION",
            4,
            parent + " spawned shell " + child + " -- likely RCE"
        )

    # Service spawning an attack tool = also very suspicious
    if parent in SUSPICIOUS_PARENTS and child in ATTACK_PROCESSES:
        return (
            "EXECUTION",
            3,
            parent + " spawned " + child + " -- suspicious service behaviour"
        )

    return None


class LineageEngine:
    """
    Tracks process parent-child relationships and flags suspicious spawn chains.

    Two data sources:
      - fork_events: gives us parent_pid -> child_pid mapping
      - exec_events (via ppid field): gives us ppid at execution time

    We maintain a pid_to_name map so we can resolve ppid -> parent process name.
    """

    def __init__(self):
        # pid -> process_name, kept as a rolling map
        # Limited to 2000 entries to prevent memory growth
        self.pid_map = {}
        self.MAX_PIDS = 2000

    def ingest_fork(self, fork_events):
        """Feed fork events to update the pid->name map."""
        for ev in fork_events:
            self._register(ev["parent_pid"], ev["parent_comm"])
            self._register(ev["child_pid"],  ev["child_comm"])

    def analyze(self, exec_events):
        """
        Check each execution event for suspicious parent-child combinations.
        Returns list of lineage alert dicts.
        """
        alerts = []

        for ev in exec_events:
            pid   = ev.get("pid")
            ppid  = ev.get("ppid")
            child = ev.get("process_name", "unknown")

            # Register this process in our map
            self._register(pid, child)

            # Skip if no parent info
            if not ppid:
                continue

            # Resolve parent name from our map
            parent = self.pid_map.get(ppid, "unknown")

            if parent == "unknown":
                continue

            # Skip explicitly trusted pairs
            if (parent, child) in TRUSTED_PAIRS:
                continue

            # Classify the combination
            result = _classify(parent, child)
            if result is None:
                continue

            phase, tier, description = result

            alerts.append({
                "source":      "LINEAGE",
                "parent_pid":  ppid,
                "parent_name": parent,
                "child_pid":   pid,
                "child_name":  child,
                "full_cmd":    ev.get("full_cmd", child),
                "phase":       phase,
                "tier":        tier,
                "mitre":       "T1059 (Command and Scripting Interpreter via " + parent + ")",
                "detail":      description,
                "timestamp":   ev.get("timestamp", ""),
            })

        return alerts

    def _register(self, pid, name):
        if pid is None or not name:
            return
        # Evict oldest entries if map is full
        if len(self.pid_map) >= self.MAX_PIDS:
            # Remove the first 200 entries (oldest)
            keys = list(self.pid_map.keys())[:200]
            for k in keys:
                del self.pid_map[k]
        self.pid_map[pid] = name
