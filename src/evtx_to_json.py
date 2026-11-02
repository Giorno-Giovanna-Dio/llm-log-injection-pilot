"""Convert EVTX files to flat JSON event lists (one dict per event).

Each event keeps System fields (EventID, Channel, Computer, TimeCreated) plus
every EventData/Data name=value pair, so the LLM and the rules see the same fields.
"""
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import Evtx.Evtx as evtx

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def record_to_dict(xml: str) -> dict:
    root = ET.fromstring(xml)
    sys_el = root.find(f"{NS}System")
    ev = {
        "EventID": int(sys_el.findtext(f"{NS}EventID")),
        "Channel": sys_el.findtext(f"{NS}Channel"),
        "Computer": sys_el.findtext(f"{NS}Computer"),
        "TimeCreated": sys_el.find(f"{NS}TimeCreated").get("SystemTime"),
        "Provider": sys_el.find(f"{NS}Provider").get("Name"),
    }
    data = root.find(f"{NS}EventData")
    if data is not None:
        for d in data.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                ev[name] = d.text or ""
    return ev


def read_evtx(path: Path) -> list[dict]:
    events = []
    with evtx.Evtx(str(path)) as log:
        for rec in log.records():
            try:
                events.append(record_to_dict(rec.xml()))
            except Exception:
                continue  # a few records in the corpus are malformed
    return events


def is_proc_create(ev: dict) -> bool:
    sysmon1 = ev["EventID"] == 1 and "Sysmon" in (ev.get("Channel") or "")
    sec4688 = ev["EventID"] == 4688 and ev.get("Channel") == "Security"
    return (sysmon1 or sec4688) and bool(ev.get("CommandLine"))


if __name__ == "__main__":
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.write_text(json.dumps(read_evtx(src), indent=1))
