"""DNS resolution, SSRF guard, optional GeoIP (DB-IP Lite mmdb in .cache/)."""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):  # malformed hostnames in source data are common
        return []
    return list(dict.fromkeys(info[4][0] for info in infos))


def resolve_all(hosts, workers: int = 32) -> dict[str, list[str]]:
    hosts = list(hosts)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return dict(zip(hosts, ex.map(_resolve, hosts)))


class Geo:
    """Country/ASN lookups; silently empty when the mmdb files are absent."""

    def __init__(self, country_path: str | None = None, asn_path: str | None = None):
        self._country = self._asn = None
        try:
            import maxminddb
            if country_path:
                self._country = maxminddb.open_database(country_path)
            if asn_path:
                self._asn = maxminddb.open_database(asn_path)
        except Exception:  # noqa: BLE001 — geo is enrichment, never fatal
            self._country = self._asn = None

    @property
    def available(self) -> bool:
        return self._country is not None

    def country(self, ip: str) -> str | None:
        if not self._country:
            return None
        try:
            row = self._country.get(ip) or {}
            return (row.get("country") or {}).get("iso_code")
        except Exception:  # noqa: BLE001
            return None

    def asn(self, ip: str) -> tuple[int | None, str | None]:
        if not self._asn:
            return None, None
        try:
            row = self._asn.get(ip) or {}
            return row.get("autonomous_system_number"), row.get("autonomous_system_organization")
        except Exception:  # noqa: BLE001
            return None, None
