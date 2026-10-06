import json
import time
from pathlib import Path


class AlertLogger:
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event_type: str, **fields):
        record = {
            "ts": time.time(),
            "event_type": event_type,
            **fields,
        }
        with open(self.log_path, "a") as f:
            f.write(json.dumps(record) + "\n")
        if event_type == "alert_critical":
            print(f"[ALERT] pid={fields.get('pid')} risk_ewma={fields.get('risk_ewma'):.3f} "
                  f"evidence={fields.get('evidence')}")
