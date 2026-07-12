"""Aggregate FlowRecords into per-IP summaries and write CSV + JSON reports."""
import csv
import json
import logging
from collections import defaultdict

import config

log = logging.getLogger("wit")

CSV_FIELDS = [
    "remote", "packets", "bytes", "protocols", "ports", "is_meta",
    "candidate_peer", "max_score", "host", "asn", "org",
    "country", "city", "latitude", "longitude", "first_seen", "last_seen",
]


def aggregate(records):
    """records: list of dicts (FlowRecord.to_dict()). Returns per-remote summary."""
    agg = {}
    for r in records:
        key = r["remote"]
        if key not in agg:
            agg[key] = {
                "remote": key,
                "packets": 0,
                "bytes": 0,
                "protocols": set(),
                "ports": set(),
                "is_meta": r["is_meta"],
                "candidate_peer": False,
                "max_score": 0,
                "host": r["host"],
                "asn": r["asn"],
                "org": r["org"],
                "country": r["country"],
                "city": r["city"],
                "latitude": r["latitude"],
                "longitude": r["longitude"],
                "first_seen": r["ts"],
                "last_seen": r["ts"],
            }
        a = agg[key]
        a["packets"] += 1
        a["bytes"] += r["length"]
        a["protocols"].add(r["proto"])
        a["ports"].add(r["dport"])
        a["candidate_peer"] = a["candidate_peer"] or r["candidate_peer"]
        a["max_score"] = max(a["max_score"], r["score"])
        a["first_seen"] = min(a["first_seen"], r["ts"])
        a["last_seen"] = max(a["last_seen"], r["ts"])
    return agg


def _serializable(a):
    d = dict(a)
    d["protocols"] = ",".join(sorted(d["protocols"]))
    d["ports"] = ",".join(str(p) for p in sorted(d["ports"]))
    return d


def write_reports(records, csv_path=None, json_path=None):
    csv_path = str(csv_path or config.CSV_REPORT)
    json_path = str(json_path or config.JSON_REPORT)

    rows = [_serializable(a) for a in aggregate(records).values()]
    rows.sort(key=lambda r: r["max_score"], reverse=True)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in CSV_FIELDS})

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    log.info("Wrote %d unique remotes to %s and %s", len(rows), csv_path, json_path)
    return rows
