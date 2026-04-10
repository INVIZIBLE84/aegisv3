# alert/notifier.py
"""
Notifier — Aegis-LX
=====================
Sends desktop notifications and writes to alerts.log.

Desktop notifications use 'notify-send' (pre-installed on Ubuntu Desktop).
For Ubuntu Server (no GUI), falls back to terminal bell + bold print.

Notification urgency levels:
  Tier 1 WATCH   → low urgency    (blue, informational)
  Tier 2 SLOW    → normal urgency (yellow, warning)
  Tier 3 CONTAIN → critical       (red, action taken)
  Tier 4 ISOLATE → critical       (red, network cut)
  Tier 5 LOCKDOWN→ critical       (magenta, manual required)
"""

import subprocess
import json
import datetime
import os

ALERTS_LOG = "alerts.log"

TIER_URGENCY = {
    1: "low",
    2: "normal",
    3: "critical",
    4: "critical",
    5: "critical",
}

TIER_ICON = {
    1: "dialog-information",
    2: "dialog-warning",
    3: "dialog-error",
    4: "dialog-error",
    5: "security-high",
}

BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"


def notify(tier: int, title: str, message: str, details: dict = None):
    """Send desktop notification + write to alerts.log."""
    _send_desktop(tier, title, message)
    _write_alert_log(tier, title, message, details or {})


def _send_desktop(tier: int, title: str, message: str):
    urgency = TIER_URGENCY.get(tier, "normal")
    icon    = TIER_ICON.get(tier, "dialog-warning")

    # Try notify-send (works on Ubuntu Desktop / any system with libnotify)
    try:
        subprocess.run(
            ["notify-send",
             "--urgency", urgency,
             "--icon", icon,
             "--app-name", "Aegis-LX",
             "--expire-time", "10000",   # 10 seconds
             title, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Server without GUI — fallback to terminal
        pass

    # Always print to terminal regardless (SOC operators watch the terminal)
    color = {1: CYAN, 2: YELLOW, 3: RED, 4: RED, 5: MAGENTA}.get(tier, RESET)
    print(f"\n  {color}{BOLD}🔔 ALERT [{title}]{RESET}")
    print(f"  {color}{message}{RESET}\n")


def _write_alert_log(tier: int, title: str, message: str, details: dict):
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "tier":      tier,
        "title":     title,
        "message":   message,
        "details":   details,
    }
    with open(ALERTS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def alert_tier_change(old_tier: int, new_tier: int, reason: str, sig_hits: list):
    """Called whenever the tier changes."""
    tier_names = {0:"NORMAL", 1:"WATCH", 2:"SLOW", 3:"CONTAIN", 4:"ISOLATE", 5:"LOCKDOWN"}

    if new_tier > old_tier:
        title   = f"Aegis-LX ⬆ Tier {new_tier}: {tier_names[new_tier]}"
        message = f"Escalated from {tier_names[old_tier]} → {tier_names[new_tier]}\n{reason}"
        hits_summary = ", ".join([h.get("mitre","")[:40] for h in sig_hits[:2]])
        if hits_summary:
            message += f"\nSignatures: {hits_summary}"
        notify(new_tier, title, message, {"reason": reason, "hits": sig_hits[:3]})

    elif new_tier < old_tier:
        title   = f"Aegis-LX ⬇ Tier {new_tier}: {tier_names[new_tier]}"
        message = f"Threat subsided. {tier_names[old_tier]} → {tier_names[new_tier]}\n{reason}"
        notify(1, title, message)   # Always low urgency for de-escalation


def alert_lockdown_prompt():
    """Prints the manual lockdown confirmation prompt."""
    print(f"""
  {MAGENTA}{BOLD}╔══════════════════════════════════════════════════════╗
  ║         ⚠  LOCKDOWN REQUESTED  ⚠                    ║
  ║  Tier 4 ISOLATE has been active. The system has      ║
  ║  detected a sustained, multi-phase attack pattern.   ║
  ║                                                      ║
  ║  To escalate to LOCKDOWN, open a new terminal and    ║
  ║  run:  sudo python3 aegis.py --lockdown              ║
  ║                                                      ║
  ║  Aegis will NOT do this automatically.               ║
  ╚══════════════════════════════════════════════════════╝{RESET}
    """)
