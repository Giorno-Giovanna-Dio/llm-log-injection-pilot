"""Sanity check: does Hayabusa on our JSON export agree with Hayabusa on the original EVTX?

For each attack sample we compare the binary verdict (any alert >= low) and the
set of rule titles. Run: .venv/bin/python tests/check_hayabusa_json.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from run_hayabusa import detected, run, run_file  # noqa: E402

agree = 0
files = sorted((ROOT / "data/samples/attack").glob("*.json"))
for f in files:
    s = json.loads(f.read_text())
    evtx = next((ROOT / "data/raw/EVTX-ATTACK-SAMPLES").rglob(s["source"]))
    a_evtx, a_json = run_file(evtx, json_input=False), run(s)
    d_evtx, d_json = detected(a_evtx), detected(a_json)
    agree += d_evtx == d_json
    r_evtx, r_json = {a["rule"] for a in a_evtx}, {a["rule"] for a in a_json}
    print(f"{s['id']} evtx={d_evtx!s:5} json={d_json!s:5} only_evtx={sorted(r_evtx - r_json)} only_json={sorted(r_json - r_evtx)}")
print(f"binary verdict agreement: {agree}/{len(files)}")
