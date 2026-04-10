# logger/logger.py
import json
import datetime

LOG_FILE = "aegis_lx.log"

class AegisLogger:
    def _write(self, event_type, message, details):
        entry = {
            "timestamp":  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event_type,
            "message":    message,
            "details":    details,
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def log_signal(self, signal):
        if signal.get("raw_weight", 0) > 0:   # Only log notable signals
            self._write("SIGNAL", f"Signal: {signal.get('signal_type')}", signal)

    def log_risk(self, data):
        self._write("RISK", f"Risk: {data.get('risk_level','?')}", data)

    def log_tier_change(self, change: dict):
        self._write("TIER_CHANGE",
                    f"Tier {change['old_tier']}→{change['new_tier']} ({change['direction']})",
                    change)

    def log_demo_event(self, phase, description):
        self._write("DEMO", f"[DEMO] {phase}: {description}", {"phase": phase})
