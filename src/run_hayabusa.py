"""Run Hayabusa (Sigma rules) on each sample and record which rules fired.

Hayabusa reads JSONL with -J: each line is one flat SIEM-export-style record
(Channel, EventID, Hostname, @timestamp, plus event fields), which Hayabusa
wraps into Event.EventData / Event.System itself (see analysis_json_file in
its src/main.rs). So we feed it the exact same events the LLM sees, including
the prompt-injected variants. tests/check_hayabusa_json.py checks that this
gives the same alerts as scanning the original EVTX.
A sample counts as "detected" if any rule at level >= low fires
(informational rules are event tagging, not alerts).
"""
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HAYABUSA_DIR = ROOT / "tools/hayabusa"
HAYABUSA = next(HAYABUSA_DIR.glob("hayabusa-*"))


def to_flat_record(ev: dict, record_number: int) -> dict:
    ts = ev["TimeCreated"].replace(" ", "T").replace("+00:00", "Z")
    rest = {k: v for k, v in ev.items() if k not in ("TimeCreated", "Provider", "Computer")}
    return {**rest, "Hostname": ev["Computer"], "SourceName": ev["Provider"],
            "RecordNumber": record_number, "@timestamp": ts}


def run_file(path: Path, json_input: bool) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.csv"
        subprocess.run([str(HAYABUSA), "dfir-timeline", *(["-J"] if json_input else []),
                        "-f", str(path), "-o", str(out),
                        "-w", "-q", "-N", "-K", "-Q", "-C", "-U", "-p", "standard"],
                       cwd=HAYABUSA_DIR, check=True, capture_output=True)
        rows = list(csv.DictReader(open(out))) if out.exists() and out.stat().st_size else []
    return [{"rule": r["RuleTitle"], "level": r["Level"]} for r in rows]


def run(sample: dict) -> list[dict]:
    """Return the alerts Hayabusa raises on one sample."""
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "sample.jsonl"
        log.write_text("\n".join(json.dumps(to_flat_record(e, i + 1))
                                 for i, e in enumerate(sample["events"])) + "\n")
        return run_file(log, json_input=True)


LEVEL_RANK = {"info": 0, "informational": 0, "low": 1, "med": 2, "medium": 2, "high": 3, "crit": 4, "critical": 4}


def detected(alerts: list[dict], min_level: str = "low") -> bool:
    return any(LEVEL_RANK.get(a["level"].lower(), 0) >= LEVEL_RANK[min_level] for a in alerts)


if __name__ == "__main__":
    sample = json.load(open(sys.argv[1]))
    for a in run(sample):
        print(a["level"], a["rule"])
