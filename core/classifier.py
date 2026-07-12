"""Turn a raw packet into a structured, enriched record and score it.

Key idea: passive capture mostly sees Meta relay servers. A *non-Meta* remote
IP appearing during media (UDP/STUN) traffic is the interesting signal — a
possible peer-to-peer endpoint. We flag those.
"""
import ipaddress
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from core.ip_filter import is_whatsapp_ip
from core.dns_resolver import reverse_dns, is_meta_hostname
from utils.geo_ip import get_geo_info

# Ports strongly associated with WhatsApp signaling / STUN media.
SIGNALING_PORTS = {443, 5222, 3478}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


@dataclass
class FlowRecord:
    ts: str
    src: str
    dst: str
    remote: str          # the non-local endpoint
    proto: str
    sport: int
    dport: int
    length: int
    is_meta: bool
    host: str
    country: str
    city: str
    latitude: float
    longitude: float
    asn: int
    org: str
    candidate_peer: bool  # non-Meta, public, media traffic => possible P2P leak
    score: int            # 0-100 "interesting" heuristic

    def to_dict(self):
        return asdict(self)


def classify(packet) -> FlowRecord | None:
    from scapy.layers.inet import IP, TCP, UDP

    if IP not in packet:
        return None

    ip = packet[IP]
    src, dst = ip.src, ip.dst

    if TCP in packet:
        proto, l4 = "TCP", packet[TCP]
    elif UDP in packet:
        proto, l4 = "UDP", packet[UDP]
    else:
        return None

    sport, dport = int(l4.sport), int(l4.dport)

    meta_src = is_whatsapp_ip(src)
    meta_dst = is_whatsapp_ip(dst)
    if not (meta_src or meta_dst):
        # Also keep media flows to public peers even if not in Meta ranges,
        # since those are exactly the candidate P2P leaks.
        if _is_private(src) == _is_private(dst):
            return None

    # Remote endpoint = the side that is not our private/local host.
    remote = dst if _is_private(src) else src
    is_meta = is_whatsapp_ip(remote)

    host = reverse_dns(remote)
    if host and is_meta_hostname(host):
        is_meta = True

    geo = get_geo_info(remote)
    if geo.get("asn") == 32934:
        is_meta = True

    is_media = proto == "UDP" and (sport not in SIGNALING_PORTS and dport not in SIGNALING_PORTS)
    candidate_peer = (not is_meta) and (not _is_private(remote)) and is_media

    score = 0
    if candidate_peer:
        score = 90
    elif not is_meta and not _is_private(remote):
        score = 60
    elif is_meta and is_media:
        score = 30

    return FlowRecord(
        ts=datetime.now(timezone.utc).isoformat(),
        src=src,
        dst=dst,
        remote=remote,
        proto=proto,
        sport=sport,
        dport=dport,
        length=len(packet),
        is_meta=is_meta,
        host=host or "",
        country=geo.get("country") or "",
        city=geo.get("city") or "",
        latitude=geo.get("latitude"),
        longitude=geo.get("longitude"),
        asn=geo.get("asn"),
        org=geo.get("org") or "",
        candidate_peer=candidate_peer,
        score=score,
    )
