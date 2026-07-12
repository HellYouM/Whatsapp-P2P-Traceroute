import json

from core.reporting import aggregate, write_reports


def _rec(remote, length, proto="UDP", dport=50000, meta=False, peer=False, score=0, ts="2026-01-01T00:00:00+00:00"):
    return {
        "ts": ts, "src": "192.168.1.5", "dst": remote, "remote": remote,
        "proto": proto, "sport": 40000, "dport": dport, "length": length,
        "is_meta": meta, "host": "", "country": "US", "city": "NY",
        "latitude": 1.0, "longitude": 2.0, "asn": 32934, "org": "Meta",
        "candidate_peer": peer, "score": score,
    }


def test_aggregate_counts_and_bytes():
    recs = [_rec("157.240.1.5", 100), _rec("157.240.1.5", 200)]
    agg = aggregate(recs)
    a = agg["157.240.1.5"]
    assert a["packets"] == 2
    assert a["bytes"] == 300


def test_write_reports_creates_files(tmp_path):
    recs = [_rec("203.0.113.9", 120, peer=True, score=90), _rec("157.240.1.5", 80, meta=True)]
    csv_p = tmp_path / "r.csv"
    json_p = tmp_path / "r.json"
    rows = write_reports(recs, csv_path=csv_p, json_path=json_p)
    assert csv_p.exists() and json_p.exists()
    # Highest score first.
    assert rows[0]["remote"] == "203.0.113.9"
    data = json.loads(json_p.read_text())
    assert len(data) == 2
