"""Auto-refresh Meta/WhatsApp IP prefixes for AS32934.

Pulls the current prefix list from RIPEstat (public BGP data) and caches it,
so the hardcoded seed list in config.py does not rot. Falls back to the seed
list on any network error.
"""
import json
import logging
import time
from datetime import datetime, timezone

import config

log = logging.getLogger("wit")

RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"


def _cache_fresh() -> bool:
    p = config.META_RANGE_CACHE
    if not p.exists():
        return False
    age_h = (time.time() - p.stat().st_mtime) / 3600
    return age_h < config.META_RANGE_MAX_AGE_HOURS


def _read_cache():
    try:
        return json.loads(config.META_RANGE_CACHE.read_text())["prefixes"]
    except Exception:
        return None


def refresh_ranges(force=False):
    """Return a list of CIDR strings. Uses cache/seed when offline."""
    if not force and _cache_fresh():
        cached = _read_cache()
        if cached:
            log.info("Loaded %d Meta prefixes from cache.", len(cached))
            return cached

    try:
        import requests

        url = RIPESTAT_URL.format(asn=config.META_ASN)
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        prefixes = [p["prefix"] for p in data["data"]["prefixes"]]
        if not prefixes:
            raise ValueError("empty prefix list")
        config.META_RANGE_CACHE.parent.mkdir(parents=True, exist_ok=True)
        config.META_RANGE_CACHE.write_text(
            json.dumps(
                {"updated": datetime.now(timezone.utc).isoformat(), "prefixes": prefixes}
            )
        )
        log.info("Refreshed %d Meta prefixes from RIPEstat (AS%d).", len(prefixes), config.META_ASN)
        return prefixes
    except Exception as e:
        log.warning("Range refresh failed (%s); using cache/seed list.", e)
        return _read_cache() or config.WHATSAPP_IP_RANGES
