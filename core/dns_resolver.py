"""Reverse-DNS resolution with caching. Helps label endpoints
(e.g. *.whatsapp.net, *.fbcdn.net) and spot non-Meta peers."""
import logging
import socket
from functools import lru_cache

log = logging.getLogger("wit")


@lru_cache(maxsize=4096)
def reverse_dns(ip: str):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


def is_meta_hostname(host) -> bool:
    if not host:
        return False
    host = host.lower()
    return any(d in host for d in ("whatsapp", "facebook", "fbcdn", "fbsv", "instagram", "1e100"))
