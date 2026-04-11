# translator/signal_translator.py
"""
Signal Translator — Aegis-LX
==============================
Converts raw eBPF process events into structured signals.

Each signal carries:
  - signal_type   : the process name (used for stat grouping)
  - phase         : which MITRE ATT&CK kill chain phase this belongs to
  - severity      : 0–30 numeric weight
  - mitre         : MITRE technique ID and name
  - context       : full command, pid, user, timestamp

KILL CHAIN PHASES (maps to Tier escalation):
  SAFE            → never escalate
  RECON           → Tier 1 WATCH
  DISCOVERY       → Tier 1/2
  CREDENTIAL      → Tier 2/3
  EXECUTION       → Tier 3
  PERSISTENCE     → Tier 3/4
  EXFILTRATION    → Tier 4
  LATERAL         → Tier 4
"""

# ── Kill chain phase constants ────────────────────────────────────────────────
PHASE_SAFE        = "SAFE"
PHASE_RECON       = "RECON"
PHASE_DISCOVERY   = "DISCOVERY"
PHASE_CREDENTIAL  = "CREDENTIAL"
PHASE_EXECUTION   = "EXECUTION"
PHASE_PERSISTENCE = "PERSISTENCE"
PHASE_EXFIL       = "EXFILTRATION"
PHASE_LATERAL     = "LATERAL"

# ── Process name dictionary ───────────────────────────────────────────────────
THREAT_DICT = {
    # Recon & Scanning
    "nmap":        {"weight": 15, "phase": PHASE_RECON,       "mitre": "T1046 (Network Service Discovery)"},
    "masscan":     {"weight": 18, "phase": PHASE_RECON,       "mitre": "T1046 (Network Service Discovery)"},
    "zmap":        {"weight": 18, "phase": PHASE_RECON,       "mitre": "T1046 (Network Service Discovery)"},
    "nuclei":      {"weight": 20, "phase": PHASE_RECON,       "mitre": "T1595 (Active Scanning)"},
    "nikto":       {"weight": 20, "phase": PHASE_RECON,       "mitre": "T1595 (Active Scanning)"},
    "gobuster":    {"weight": 18, "phase": PHASE_RECON,       "mitre": "T1083 (File/Dir Discovery)"},
    "ffuf":        {"weight": 18, "phase": PHASE_RECON,       "mitre": "T1083 (File/Dir Discovery)"},
    "wfuzz":       {"weight": 18, "phase": PHASE_RECON,       "mitre": "T1083 (File/Dir Discovery)"},
    "dirbuster":   {"weight": 18, "phase": PHASE_RECON,       "mitre": "T1083 (File/Dir Discovery)"},

    # Discovery
    "linpeas":     {"weight": 28, "phase": PHASE_DISCOVERY,   "mitre": "T1082 (System Information Discovery)"},
    "linenum":     {"weight": 28, "phase": PHASE_DISCOVERY,   "mitre": "T1082 (System Information Discovery)"},
    "pspy":        {"weight": 20, "phase": PHASE_DISCOVERY,   "mitre": "T1057 (Process Discovery)"},
    "id":          {"weight":  5, "phase": PHASE_DISCOVERY,   "mitre": "T1033 (System Owner Discovery)"},
    "whoami":      {"weight":  5, "phase": PHASE_DISCOVERY,   "mitre": "T1033 (System Owner Discovery)"},
    "uname":       {"weight":  3, "phase": PHASE_DISCOVERY,   "mitre": "T1082 (System Info)"},

    # Network utilities — suspicious in server context
    "nc":          {"weight": 22, "phase": PHASE_EXECUTION,   "mitre": "T1095 (Non-Application Layer Protocol)"},
    "ncat":        {"weight": 22, "phase": PHASE_EXECUTION,   "mitre": "T1095 (Non-Application Layer Protocol)"},
    "socat":       {"weight": 20, "phase": PHASE_EXECUTION,   "mitre": "T1095 (Non-Application Layer Protocol)"},
    "netcat":      {"weight": 22, "phase": PHASE_EXECUTION,   "mitre": "T1095 (Non-Application Layer Protocol)"},

    # Exploitation frameworks
    "msfconsole":  {"weight": 30, "phase": PHASE_EXECUTION,   "mitre": "T1203 (Exploitation for Client Execution)"},
    "msfvenom":    {"weight": 30, "phase": PHASE_EXECUTION,   "mitre": "T1587.001 (Develop Capabilities: Malware)"},
    "sqlmap":      {"weight": 25, "phase": PHASE_EXECUTION,   "mitre": "T1190 (Exploit Public-Facing Application)"},
    "hydra":       {"weight": 25, "phase": PHASE_CREDENTIAL,  "mitre": "T1110 (Brute Force)"},
    "medusa":      {"weight": 25, "phase": PHASE_CREDENTIAL,  "mitre": "T1110 (Brute Force)"},
    "john":        {"weight": 20, "phase": PHASE_CREDENTIAL,  "mitre": "T1110.002 (Password Cracking)"},
    "hashcat":     {"weight": 20, "phase": PHASE_CREDENTIAL,  "mitre": "T1110.002 (Password Cracking)"},

    # Exfiltration helpers
    "ftp":         {"weight": 10, "phase": PHASE_EXFIL,       "mitre": "T1048 (Exfiltration Over Alt Protocol)"},
    "tftp":        {"weight": 15, "phase": PHASE_EXFIL,       "mitre": "T1048 (Exfiltration Over Alt Protocol)"},

    # Low-weight tools needing arg context
    "curl":        {"weight":  4, "phase": PHASE_SAFE,        "mitre": "T1105 (context needed)"},
    "wget":        {"weight":  4, "phase": PHASE_SAFE,        "mitre": "T1105 (context needed)"},
    "python3":     {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "python":      {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "perl":        {"weight":  3, "phase": PHASE_SAFE,        "mitre": "T1059.006 (context needed)"},

    # Explicitly safe
    "bash":        {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "sh":          {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "zsh":         {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "apt":         {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "apt-get":     {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "dpkg":        {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "sudo":        {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "systemctl":   {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "git":         {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "ssh":         {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "vim":         {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "nano":        {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "ls":          {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "cat":         {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "grep":        {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "ping":        {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "iptables":    {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "ip6tables":   {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
    "cpulimit":    {"weight":  0, "phase": PHASE_SAFE,        "mitre": "SAFE"},
}

# ── Argument-level threat patterns ────────────────────────────────────────────
# ALL matches are accumulated — no early break.
SUSPICIOUS_ARGS = {
    # Credential access
    "/etc/shadow":     {"weight": 25, "phase": PHASE_CREDENTIAL,  "mitre": "T1003.008 (/etc/shadow Access)"},
    "/etc/passwd":     {"weight": 10, "phase": PHASE_DISCOVERY,   "mitre": "T1003.008 (Passwd File Access)"},
    "/etc/sudoers":    {"weight": 20, "phase": PHASE_CREDENTIAL,  "mitre": "T1548.003 (Sudo Config Access)"},

    # SSH key theft
    "id_rsa":          {"weight": 20, "phase": PHASE_CREDENTIAL,  "mitre": "T1552.004 (SSH Private Key)"},
    "id_ed25519":      {"weight": 20, "phase": PHASE_CREDENTIAL,  "mitre": "T1552.004 (SSH Private Key)"},
    "authorized_keys": {"weight": 18, "phase": PHASE_PERSISTENCE, "mitre": "T1098.004 (SSH Authorized Keys)"},
    ".ssh/":           {"weight": 10, "phase": PHASE_CREDENTIAL,  "mitre": "T1552.004 (SSH Dir Access)"},

    # Obfuscation
    "base64 -d":       {"weight": 15, "phase": PHASE_EXECUTION,   "mitre": "T1140 (Deobfuscate Files)"},
    "base64 -D":       {"weight": 15, "phase": PHASE_EXECUTION,   "mitre": "T1140 (Deobfuscate Files)"},
    "| bash":          {"weight": 20, "phase": PHASE_EXECUTION,   "mitre": "T1059.004 (Pipe to Shell)"},
    "| sh":            {"weight": 20, "phase": PHASE_EXECUTION,   "mitre": "T1059.004 (Pipe to Shell)"},
    "eval $(":         {"weight": 18, "phase": PHASE_EXECUTION,   "mitre": "T1059.004 (Eval Execution)"},

    # Reverse shell patterns
    "nc -e ":           {"weight": 25, "phase": PHASE_EXECUTION,   "mitre": "T1059.004 (NC Reverse Shell -e flag)"},
    "nc -c ":           {"weight": 25, "phase": PHASE_EXECUTION,   "mitre": "T1059.004 (NC Reverse Shell -c flag)"},
    "ncat -e ":         {"weight": 25, "phase": PHASE_EXECUTION,   "mitre": "T1059.004 (Ncat Reverse Shell)"},
    "-nvlp ":           {"weight": 18, "phase": PHASE_EXECUTION,   "mitre": "T1095 (Netcat Listener)"},
    "-lvnp ":           {"weight": 18, "phase": PHASE_EXECUTION,   "mitre": "T1095 (Netcat Listener)"},
    "-lnvp ":           {"weight": 18, "phase": PHASE_EXECUTION,   "mitre": "T1095 (Netcat Listener)"},
    "/dev/tcp/":        {"weight": 25, "phase": PHASE_EXECUTION,   "mitre": "T1059.004 (Bash TCP Reverse Shell)"},
    "/dev/udp/":       {"weight": 25, "phase": PHASE_EXECUTION,   "mitre": "T1059.004 (Bash UDP Reverse Shell)"},
    "mkfifo":          {"weight": 20, "phase": PHASE_EXECUTION,   "mitre": "T1059.004 (Named Pipe Shell)"},
    "0>&1":            {"weight": 22, "phase": PHASE_EXECUTION,   "mitre": "T1059.004 (FD Redirect Shell)"},

    # Privilege escalation
    "chmod +s":        {"weight": 22, "phase": PHASE_EXECUTION,   "mitre": "T1548.001 (SUID Bit Set)"},
    "chmod 4755":      {"weight": 22, "phase": PHASE_EXECUTION,   "mitre": "T1548.001 (SUID Bit Set)"},
    "chown root":      {"weight": 15, "phase": PHASE_EXECUTION,   "mitre": "T1548 (Abuse Elevation Control)"},

    # Persistence
    "/etc/cron":       {"weight": 18, "phase": PHASE_PERSISTENCE, "mitre": "T1053.003 (Cron Persistence)"},
    "crontab -e":      {"weight": 15, "phase": PHASE_PERSISTENCE, "mitre": "T1053.003 (Cron Modification)"},
    ".bashrc":         {"weight": 12, "phase": PHASE_PERSISTENCE, "mitre": "T1546.004 (Bash Profile)"},
    ".bash_profile":   {"weight": 12, "phase": PHASE_PERSISTENCE, "mitre": "T1546.004 (Bash Profile)"},
    "/etc/profile":    {"weight": 15, "phase": PHASE_PERSISTENCE, "mitre": "T1546.004 (Profile Persistence)"},

    # Exfiltration
    "| nc ":           {"weight": 22, "phase": PHASE_EXFIL,       "mitre": "T1048 (Exfil via Netcat)"},
    "| nc	":          {"weight": 22, "phase": PHASE_EXFIL,       "mitre": "T1048 (Exfil via Netcat)"},
    "tar czf - ":      {"weight": 20, "phase": PHASE_EXFIL,       "mitre": "T1048 (Data Staged for Exfil)"},
    "tar cfz - ":      {"weight": 20, "phase": PHASE_EXFIL,       "mitre": "T1048 (Data Staged for Exfil)"},
    "| curl ":         {"weight": 15, "phase": PHASE_EXFIL,       "mitre": "T1048 (Exfil via Curl)"},
    "| wget ":         {"weight": 15, "phase": PHASE_EXFIL,       "mitre": "T1048 (Exfil via Wget)"},

    # Memory / credential dump
    "/proc/mem":       {"weight": 25, "phase": PHASE_CREDENTIAL,  "mitre": "T1003 (Memory Credential Dump)"},
    "/proc/kcore":     {"weight": 25, "phase": PHASE_CREDENTIAL,  "mitre": "T1003 (Kernel Memory Read)"},
    "gcore":           {"weight": 20, "phase": PHASE_CREDENTIAL,  "mitre": "T1003 (Process Memory Dump)"},
}


def translate_process_to_signals(process_info: dict) -> list:
    full_command = process_info.get("full_cmd", "unknown")
    process_name = process_info.get("process_name", "unknown")

    weight     = 0
    phase      = PHASE_SAFE
    mitre_tags = []

    # Step 1: Base command lookup
    if process_name in THREAT_DICT:
        entry = THREAT_DICT[process_name]
        if entry["weight"] > 0:
            weight += entry["weight"]
            phase   = entry["phase"]
            mitre_tags.append(entry["mitre"])

    # Step 2: Argument pattern scan — accumulate ALL matches
    for pattern, rules in SUSPICIOUS_ARGS.items():
        if pattern in full_command:
            weight += rules["weight"]
            mitre_tags.append(rules["mitre"])
            # Escalate phase to the most severe match
            if rules["weight"] > weight * 0.5:
                phase = rules["phase"]

    weight    = min(weight, 30)
    mitre_tag = " | ".join(mitre_tags) if mitre_tags else "SAFE/UNMAPPED"

    return [{
        "signal_type": process_name,
        "phase":       phase,
        "severity":    weight,
        "raw_weight":  weight,
        "mitre":       mitre_tag,
        "context": {
            "full_cmd":  full_command,
            "pid":       process_info.get("pid"),
            "user":      process_info.get("user", "unknown"),
            "timestamp": process_info.get("timestamp"),
        }
    }]
