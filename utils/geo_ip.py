"""Geolocation + ASN enrichment.

Readers are opened once and reused. Lookups are cached per IP. Missing
databases degrade gracefully (return partial/empty data) instead of crashing.
"""
import logging
from functools import lru_cache

import geoip2.database
import geoip2.errors

import config

log = logging.getLogger("wit")

_city_reader = None
_asn_reader = None
_warned = set()


def _get_reader(kind):
    global _city_reader, _asn_reader
    if kind == "city":
        if _city_reader is None:
            _city_reader = _open(config.GEO_CITY_DB, "city")
        return _city_reader
    if _asn_reader is None:
        _asn_reader = _open(config.GEO_ASN_DB, "asn")
    return _asn_reader


def _open(path, kind):
    try:
        return geoip2.database.Reader(path)
    except FileNotFoundError:
        if kind not in _warned:
            log.warning("GeoLite2 %s DB not found at %s; enrichment disabled for it.", kind, path)
            _warned.add(kind)
        return False  # sentinel: tried and failed


@lru_cache(maxsize=4096)
def get_geo_info(ip: str) -> dict:
    info = {
        "ip": ip,
        "country": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "org": None,
    }

    city = _get_reader("city")
    if city:
        try:
            r = city.city(ip)
            info.update(
                country=r.country.name,
                city=r.city.name,
                latitude=r.location.latitude,
                longitude=r.location.longitude,
            )
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            log.debug("City lookup failed for %s: %s", ip, e)

    asn = _get_reader("asn")
    if asn:
        try:
            r = asn.asn(ip)
            info.update(asn=r.autonomous_system_number, org=r.autonomous_system_organization)
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            log.debug("ASN lookup failed for %s: %s", ip, e)

    return info


def close():
    for reader in (_city_reader, _asn_reader):
        if reader:
            try:
                reader.close()
            except Exception:
                pass
