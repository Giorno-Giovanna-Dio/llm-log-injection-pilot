"""List every EVTX file in the attack corpus with its process-creation counts."""
import csv
import sys
from pathlib import Path

from evtx_to_json import is_proc_create, read_evtx

root = Path(sys.argv[1])
w = csv.writer(sys.stdout)
w.writerow(["tactic", "file", "n_events", "n_proc_create"])
for p in sorted(root.rglob("*.evtx")):
    try:
        evs = read_evtx(p)
    except Exception as e:
        print(f"skip {p}: {e}", file=sys.stderr)
        continue
    w.writerow([p.relative_to(root).parts[0], p.name, len(evs), sum(map(is_proc_create, evs))])
