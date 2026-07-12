# WhatsApp IP Tracker

Network traffic analyzer for **WhatsApp / Meta** flows. Captures packets on an
interface you control, filters Meta (AS32934) traffic, enriches each remote
endpoint with geolocation + ASN + reverse-DNS, and flags **candidate
peer-to-peer endpoints** — non-Meta public IPs seen during media traffic, the
only realistic way passive capture reveals a real peer rather than a relay.

> ⚠️ **Authorized / educational use only.** Capture only traffic on networks you
> own or are explicitly permitted to monitor. Using this to locate or
> deanonymize a person without consent may violate privacy and anti-stalking
> laws. You are responsible for lawful use.

## What it does

- Capture **TCP + UDP** (signaling *and* media), not UDP-only.
- Meta prefix list **auto-refreshed** from RIPEstat (BGP, AS32934), cached, with
  an offline seed fallback — no more stale hardcoded ranges.
- Geo + **ASN** enrichment via MaxMind GeoLite2, readers opened once and cached.
- **Heuristic scoring**: Meta relay vs remote vs candidate P2P peer.
- Reports to **CSV + JSON**, ranked by "interesting" score.
- Optional **live web dashboard** (FastAPI + WebSocket) with a geo map and feed.

## Reality check

Modern WhatsApp calls are usually **relayed through Meta TURN servers**, so most
captured IPs are Meta's, not the other person's. A direct peer IP only leaks in
narrow P2P cases — this tool surfaces those as `candidate_peer`, but there is no
guarantee any appear. Treat "get someone's IP from WhatsApp" as mostly a myth.

## Install

```bash
pip install -r requirements.txt          # or: pip install -e ".[dev]"
cp .env.example .env                      # optional tuning
# Windows: install Npcap (https://npcap.com) for capture.
# Download GeoLite2-City.mmdb + GeoLite2-ASN.mmdb into ./data (free MaxMind acct).
```

## Usage

```bash
# CLI capture (needs Administrator / sudo)
sudo python main.py --count 500
python main.py --iface "Wi-Fi" --timeout 60
python main.py --no-refresh              # skip online range refresh (offline)

# Live dashboard
python main.py --dashboard               # http://127.0.0.1:8000
```

Outputs: `output/ip_report.csv`, `output/ip_report.json`, `logs/packet_logs.pcap`.

## Tests

```bash
pytest
```

## Docker

```bash
docker build -t wit .
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN -p 8000:8000 wit --dashboard
```

## Architecture

```
main.py              CLI entrypoint (capture | --dashboard)
config.py            env-driven settings + seed Meta ranges
core/
  meta_ranges.py     RIPEstat AS32934 prefix auto-refresh + cache
  ip_filter.py       guarded CIDR membership, pre-parsed networks
  classifier.py      packet -> enriched FlowRecord + peer scoring
  packet_sniffer.py  scapy capture, iface auto-detect, live callback
  reporting.py       per-IP aggregation -> CSV/JSON
  dns_resolver.py    cached reverse-DNS + Meta-hostname check
utils/
  geo_ip.py          GeoLite2 city+ASN, open-once, LRU cache
  helpers.py         logging, admin check, dir setup
dashboard/           FastAPI + WebSocket + offline canvas map
tests/               pytest suite (ip_filter, classifier, reporting)
```
