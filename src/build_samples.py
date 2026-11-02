"""Build the 20 attack + 20 benign samples as JSON event lists.

Attack: each sample is one whole EVTX file from EVTX-ATTACK-SAMPLES listed in
data/attack_selection.csv (label = folder tactic + technique from the file name).

Benign: windows of consecutive events cut from the Sysmon log of
NextronSystems/evtx-baseline (win10-client), a goodware-only recording.
The 800 MB log is too big to parse whole, so we take 20 evenly spaced
64 KB chunks (skipping the first and last 5%), and in each chunk take a run of
consecutive events that starts at the first process-creation event with a
CommandLine. Window length i copies attack sample i's event count (capped at
40) so both classes have similar sizes. Fully deterministic.
"""
import csv
import json
from pathlib import Path

import Evtx.Evtx as evtx

from evtx_to_json import is_proc_create, read_evtx, record_to_dict

ROOT = Path(__file__).resolve().parent.parent
ATTACK_DIR = ROOT / "data/raw/EVTX-ATTACK-SAMPLES"
BENIGN_EVTX = ROOT / "data/raw/evtx-baseline/Logs_Client/Microsoft-Windows-Sysmon%4Operational.evtx"
OUT = ROOT / "data/samples"
MAX_BENIGN_LEN = 40


def build_attack() -> list[int]:
    sizes = []
    rows = list(csv.DictReader(open(ROOT / "data/attack_selection.csv")))
    for i, row in enumerate(rows):
        path = next(ATTACK_DIR.rglob(row["file"]))
        events = read_evtx(path)
        sizes.append(len(events))
        sample = {"id": f"attack_{i:02d}", "label": "malicious", "source": row["file"],
                  "tactic": row["tactic"], "technique_id": row["technique_id"], "events": events}
        (OUT / "attack" / f"{sample['id']}.json").write_text(json.dumps(sample, indent=1))
    return sizes


def build_benign(sizes: list[int]) -> None:
    with evtx.Evtx(str(BENIGN_EVTX)) as log:
        n_chunks = log.get_file_header().chunk_count()
        lo, hi = int(n_chunks * 0.05), int(n_chunks * 0.95)
        picks = [lo + (hi - lo) * k // len(sizes) for k in range(len(sizes))]
        i = 0
        for idx, chunk in enumerate(log.chunks()):
            if i == len(picks):
                break
            if idx < picks[i]:
                continue
            # if the picked chunk has no process creation, move on to the next chunk
            events = [record_to_dict(r.xml()) for r in chunk.records()]
            start = next((j for j, ev in enumerate(events) if is_proc_create(ev)), None)
            if start is None:
                continue
            window = events[start:start + min(sizes[i], MAX_BENIGN_LEN)]
            sample = {"id": f"benign_{i:02d}", "label": "benign", "source": f"win10-client sysmon chunk {idx}",
                      "tactic": "", "technique_id": "", "events": window}
            (OUT / "benign" / f"{sample['id']}.json").write_text(json.dumps(sample, indent=1))
            i += 1


if __name__ == "__main__":
    for d in ("attack", "benign"):
        (OUT / d).mkdir(parents=True, exist_ok=True)
    build_benign(build_attack())
