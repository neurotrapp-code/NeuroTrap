"""Real GeoIP resolution for the dashboard heatmap (Day 32-33).

Uses a MaxMind GeoLite2-City database (``GEOIP_DB`` env, default
``data/GeoLite2-City.mmdb``). If the DB or the ``geoip2`` package is absent, or
the IP isn't found (e.g. RFC1918 lab addresses), it returns ``None`` — the map
simply shows no point. It never fabricates coordinates, so every plotted point is
a real geolocation.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Optional

_DEFAULT_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "GeoLite2-City.mmdb")
GEOIP_DB = os.environ.get("GEOIP_DB", _DEFAULT_DB)

_reader = None
_tried = False


def _get_reader():
    global _reader, _tried
    if _tried:
        return _reader
    _tried = True
    try:
        import geoip2.database
        if os.path.exists(GEOIP_DB):
            _reader = geoip2.database.Reader(GEOIP_DB)
    except Exception:
        _reader = None
    return _reader


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def locate(ip: str) -> Optional[dict]:
    """Return ``{lat, lon, country, city}`` for a public IP, or None."""
    if not _is_public(ip):
        return None
    reader = _get_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
        if r.location.latitude is None:
            return None
        return {
            "lat": r.location.latitude,
            "lon": r.location.longitude,
            "country": r.country.iso_code,
            "city": r.city.name,
        }
    except Exception:
        return None


def available() -> bool:
    return _get_reader() is not None
