"""
AdaptShield Event Sources
=========================
Defines the EventSource protocol and three concrete implementations:
1. SimulatedSource: Virtual processes driven by data/scenarios/*.json with seed and speed control.
2. ReplaySource: Replays labeled trace CSV files grouped by PID with speed control.
3. LiveAgentSource: Feature-flagged stub reading live agent JSONL event logs (marked unverified).
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import numpy as np
import pandas as pd

from adaptshield.feature_aggregator import FEATURE_COLUMNS
from scripts.make_datasets import simulate_run_windows


class EventSource(ABC):
    """Abstract interface for streaming feature windows to the pipeline."""

    @abstractmethod
    def reset(self) -> None:
        """Resets the source to the initial window state."""
        pass

    @abstractmethod
    def has_next(self) -> bool:
        """Returns True if more evaluation windows remain."""
        pass

    @abstractmethod
    def next_window(self) -> Optional[Dict[str, Any]]:
        """Retrieves the next evaluation window row."""
        pass

    @abstractmethod
    def stream_all(self, sleep_delay: bool = False) -> Iterator[Dict[str, Any]]:
        """Yields all evaluation windows sequentially."""
        pass


class SimulatedSource(EventSource):
    """
    Virtual process event generator driven by data/scenarios/*.json definitions.
    Supports deterministic seeding and speed multipliers (1x, 5x, 20x).
    """

    def __init__(
        self,
        scenario: str | Dict[str, Any],
        scenarios_dir: Path | str = "data/scenarios",
        seed: int = 42,
        speed: float = 1.0,
    ):
        self.scenarios_dir = Path(scenarios_dir)
        self.seed = seed
        self.speed = max(0.1, speed)
        self.scenario_config = self._load_scenario(scenario)
        self._windows: List[Dict[str, Any]] = []
        self._current_idx: int = 0
        self.reset()

    def _load_scenario(self, scenario: str | Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(scenario, dict):
            return scenario
        # Load from JSON file
        scenario_file = self.scenarios_dir / f"{scenario}.json"
        if not scenario_file.exists():
            # Check with exact path
            scenario_file = Path(scenario)
        if not scenario_file.exists():
            raise FileNotFoundError(f"Scenario not found: {scenario}")
        with open(scenario_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def reset(self) -> None:
        self._windows.clear()
        self._current_idx = 0
        rng = np.random.default_rng(self.seed)

        sc = self.scenario_config
        scenario_id = sc.get("id", "custom")
        family = sc.get("family", "benign")
        variant = sc.get("variant", "generic")
        duration_windows = sc.get("duration_windows", 20)
        window_seconds = sc.get("window_seconds", 2.0)
        processes = sc.get("processes", [
            {"pid": 1001, "name": "proc_default", "role": family, "behavior": variant}
        ])

        # Generate window trace for each process in the scenario
        proc_dfs: List[pd.DataFrame] = []
        base_time = 1728000000.0

        VALID_VARIANTS = {
            "fast", "slow_and_low", "intermittent", "partial_encryption",
            "rename_then_encrypt", "delete_original", "mimicry", "office_worker",
            "developer_build", "backup_tar", "backup_restic", "oltp_postgres", "oltp_mysql"
        }

        for proc in processes:
            pid = proc.get("pid", int(rng.integers(1050, 50000)))
            proc_role = proc.get("role", family)
            raw_behavior = proc.get("behavior", variant)
            if raw_behavior in VALID_VARIANTS:
                proc_behavior = raw_behavior
            elif variant in VALID_VARIANTS:
                proc_behavior = variant
            elif proc_role == "ransomware":
                proc_behavior = "fast"
            else:
                proc_behavior = "office_worker" if proc_role == "benign" else ("backup_restic" if proc_role == "backup" else "oltp_postgres")

            run_id = f"sim_{scenario_id}_{pid}"

            df = simulate_run_windows(
                run_id=run_id,
                pid=pid,
                label=proc_role if proc_role in ["benign", "backup", "oltp", "ransomware"] else family,
                scenario=scenario_id,
                variant=proc_behavior,
                n_windows=duration_windows,
                rng=rng,
                base_timestamp=base_time,
                window_seconds=window_seconds,
            )
            df["process_name"] = proc.get("name", f"proc_{pid}")
            proc_dfs.append(df)

        if not proc_dfs:
            return

        # Interleave windows chronologically by window_idx across all processes
        combined = pd.concat(proc_dfs, ignore_index=True)
        combined = combined.sort_values(by=["window_idx", "pid"]).reset_index(drop=True)
        self._windows = combined.to_dict(orient="records")

    def has_next(self) -> bool:
        return self._current_idx < len(self._windows)

    def next_window(self) -> Optional[Dict[str, Any]]:
        if not self.has_next():
            return None
        win = self._windows[self._current_idx]
        self._current_idx += 1
        return win

    def stream_all(self, sleep_delay: bool = False) -> Iterator[Dict[str, Any]]:
        self.reset()
        window_sec = self.scenario_config.get("window_seconds", 2.0)
        delay = (window_sec / self.speed) if sleep_delay else 0.0

        while self.has_next():
            win = self.next_window()
            if win is None:
                break
            if delay > 0:
                time.sleep(delay)
            yield win


class ReplaySource(EventSource):
    """
    Replays historical labeled trace CSVs grouped by PID with speed control.
    """

    def __init__(self, csv_path: Path | str, speed: float = 1.0, loop: bool = False):
        self.csv_path = Path(csv_path)
        if not self.csv_path.exists():
            raise FileNotFoundError(f"Trace CSV file not found: {self.csv_path}")
        self.speed = max(0.1, speed)
        self.loop = loop
        self._records: List[Dict[str, Any]] = []
        self._current_idx: int = 0
        self.reset()

    def reset(self) -> None:
        self._current_idx = 0
        df = pd.read_csv(self.csv_path)
        # Ensure ordered by window_idx / timestamp
        sort_cols = [c for c in ["window_idx", "timestamp"] if c in df.columns]
        if sort_cols:
            df = df.sort_values(by=sort_cols).reset_index(drop=True)
        self._records = df.to_dict(orient="records")

    def has_next(self) -> bool:
        return self._current_idx < len(self._records)

    def next_window(self) -> Optional[Dict[str, Any]]:
        if not self.has_next():
            if self.loop and self._records:
                self.reset()
            else:
                return None
        row = self._records[self._current_idx]
        self._current_idx += 1
        return row

    def stream_all(self, sleep_delay: bool = False) -> Iterator[Dict[str, Any]]:
        self.reset()
        delay = (2.0 / self.speed) if sleep_delay else 0.0
        while self.has_next():
            row = self.next_window()
            if row is None:
                break
            if delay > 0:
                time.sleep(delay)
            yield row


class LiveAgentSource(EventSource):
    """
    Feature-flagged stub that reads real Linux agent JSONL logs.
    Marked explicitly as unverified until validated on a live Ubuntu VM with root.
    """

    def __init__(self, log_path: Path | str = "/var/log/adaptshield/alert.jsonl", enabled: bool = False):
        self.log_path = Path(log_path)
        self.enabled = enabled
        self.unverified = True
        self._cursor: int = 0

    def reset(self) -> None:
        self._cursor = 0

    def has_next(self) -> bool:
        if not self.enabled or not self.log_path.exists():
            return False
        return self.log_path.stat().st_size > self._cursor

    def next_window(self) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        if not self.log_path.exists():
            return None

        with open(self.log_path, "r", encoding="utf-8") as f:
            f.seek(self._cursor)
            line = f.readline()
            self._cursor = f.tell()

        if not line:
            return None

        try:
            record = json.loads(line)
            record["unverified"] = True
            record["source"] = "live_agent"
            return record
        except Exception:
            return None

    def stream_all(self, sleep_delay: bool = False) -> Iterator[Dict[str, Any]]:
        while self.has_next():
            item = self.next_window()
            if item:
                yield item
