"""Geolocation, reverse DNS and ASN lookup for remote endpoints.

Design notes
------------
* Only **public, routable** addresses ever leave the machine.  Private, link
  local, loopback and multicast addresses are labelled locally.
* Results are cached on disk (``~/.cache/netmonguru/geoip.json``) for 30 days,
  so a busy machine typically performs a handful of lookups per session.
* Lookups happen on a background thread; the UI never blocks on the network.
* ``ip-api.com`` is used by default (free, no key, 15 batch requests/minute).
  Set ``--mmdb /path/to/GeoLite2-City.mmdb`` to stay fully offline instead, or
  ``--no-geo`` to disable outbound lookups entirely.
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .models import GeoInfo, is_routable

CACHE_TTL = 30 * 24 * 3600
BATCH_URL = ("http://ip-api.com/batch?fields=status,message,country,"
             "countryCode,city,lat,lon,isp,org,as,query")
SELF_URL = ("http://ip-api.com/json/?fields=status,country,countryCode,city,"
            "lat,lon,isp,org,as,query")
BATCH_SIZE = 100
MIN_INTERVAL = 4.5          # seconds between batch calls (free tier: 15/min)
USER_AGENT = "netmonguru/1.0 (+local network monitor)"


def cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "netmonguru" / "geoip.json"


# ---------------------------------------------------------------------------
# providers
# ---------------------------------------------------------------------------

class IpApiProvider:
    """Batch lookups against the free ip-api.com endpoint."""

    name = "ip-api"

    def __init__(self) -> None:
        self._last_call = 0.0
        self.error = ""

    def lookup_self(self) -> Optional[GeoInfo]:
        """Where this machine appears to be, used as the map's home marker."""
        try:
            req = urllib.request.Request(
                SELF_URL, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=10) as resp:
                entry = json.loads(resp.read().decode())
        except Exception:                             # noqa: BLE001
            return None
        if entry.get("status") != "success":
            return None
        return GeoInfo(ip=entry.get("query", ""), lat=entry.get("lat"),
                       lon=entry.get("lon"), city=entry.get("city") or "",
                       country=entry.get("country") or "",
                       country_code=entry.get("countryCode") or "",
                       org=entry.get("org") or entry.get("isp") or "",
                       asn=entry.get("as") or "", source="api")

    def lookup(self, ips: List[str]) -> Dict[str, GeoInfo]:
        out: Dict[str, GeoInfo] = {}
        for i in range(0, len(ips), BATCH_SIZE):
            chunk = ips[i:i + BATCH_SIZE]
            wait = MIN_INTERVAL - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()
            try:
                payload = json.dumps(chunk).encode()
                req = urllib.request.Request(
                    BATCH_URL, data=payload,
                    headers={"Content-Type": "application/json",
                             "User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=12) as resp:
                    data = json.loads(resp.read().decode())
            except (urllib.error.URLError, TimeoutError, OSError,
                    json.JSONDecodeError) as exc:
                self.error = f"{type(exc).__name__}: {exc}"[:160]
                break
            self.error = ""
            for entry in data if isinstance(data, list) else []:
                ip = entry.get("query") or ""
                if not ip:
                    continue
                if entry.get("status") != "success":
                    out[ip] = GeoInfo(ip=ip, source="api")
                    continue
                out[ip] = GeoInfo(
                    ip=ip,
                    lat=entry.get("lat"), lon=entry.get("lon"),
                    city=entry.get("city") or "",
                    country=entry.get("country") or "",
                    country_code=entry.get("countryCode") or "",
                    org=entry.get("org") or entry.get("isp") or "",
                    asn=entry.get("as") or "",
                    source="api")
        return out


class IpWhoIsProvider:
    """HTTPS single-IP fallback, used when the batch endpoint is blocked."""

    name = "ipwho.is"
    url = "https://ipwho.is/{ip}"

    def __init__(self) -> None:
        self.error = ""

    def lookup(self, ips: List[str]) -> Dict[str, GeoInfo]:
        out: Dict[str, GeoInfo] = {}
        for ip in ips[:40]:
            try:
                req = urllib.request.Request(
                    self.url.format(ip=ip),
                    headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    entry = json.loads(resp.read().decode())
            except Exception as exc:                  # noqa: BLE001
                self.error = f"{type(exc).__name__}: {exc}"[:160]
                break
            self.error = ""
            if not entry.get("success"):
                out[ip] = GeoInfo(ip=ip, source="api")
                continue
            conn = entry.get("connection") or {}
            asn = conn.get("asn")
            out[ip] = GeoInfo(
                ip=ip, lat=entry.get("latitude"), lon=entry.get("longitude"),
                city=entry.get("city") or "",
                country=entry.get("country") or "",
                country_code=entry.get("country_code") or "",
                org=conn.get("org") or conn.get("isp") or "",
                asn=f"AS{asn}" if asn else "", source="api")
            time.sleep(0.15)
        return out


class ChainProvider:
    """Try ip-api's batch endpoint; fall back to ipwho.is if it is blocked."""

    name = "chain"

    def __init__(self) -> None:
        self.primary = IpApiProvider()
        self.secondary = IpWhoIsProvider()
        self.active = self.primary
        self.error = ""

    def lookup_self(self) -> Optional[GeoInfo]:
        return self.primary.lookup_self()

    def lookup(self, ips: List[str]) -> Dict[str, GeoInfo]:
        out = self.active.lookup(ips)
        if not out and self.active is self.primary:
            self.active = self.secondary
            out = self.secondary.lookup(ips)
        self.error = self.active.error
        return out


class MmdbProvider:
    """Fully offline lookups from a MaxMind GeoLite2-City database."""

    name = "mmdb"

    def __init__(self, path: str, asn_path: str = "") -> None:
        import geoip2.database                       # optional dependency

        self.reader = geoip2.database.Reader(path)
        self.asn_reader = None
        if asn_path:
            self.asn_reader = geoip2.database.Reader(asn_path)
        self.error = ""

    def lookup(self, ips: List[str]) -> Dict[str, GeoInfo]:
        out: Dict[str, GeoInfo] = {}
        for ip in ips:
            info = GeoInfo(ip=ip, source="mmdb")
            try:
                r = self.reader.city(ip)
                info.lat = r.location.latitude
                info.lon = r.location.longitude
                info.city = r.city.name or ""
                info.country = r.country.name or ""
                info.country_code = r.country.iso_code or ""
            except Exception:                        # noqa: BLE001
                pass
            if self.asn_reader is not None:
                try:
                    a = self.asn_reader.asn(ip)
                    info.asn = f"AS{a.autonomous_system_number}"
                    info.org = a.autonomous_system_organization or ""
                except Exception:                    # noqa: BLE001
                    pass
            out[ip] = info
        return out


# ---------------------------------------------------------------------------
# enricher
# ---------------------------------------------------------------------------

def _local_info(ip: str) -> GeoInfo:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return GeoInfo(ip=ip, country="unknown", source="local")
    if addr.is_loopback:
        label = "loopback"
    elif addr.is_multicast:
        label = "multicast"
    elif addr.is_link_local:
        label = "link-local"
    else:
        label = "LAN"
    return GeoInfo(ip=ip, country=label, org=label, source="local")


class Enricher:
    """Background geo/DNS/ASN resolver with a persistent cache."""

    def __init__(self, enabled: bool = True, resolve_dns: bool = True,
                 mmdb: str = "", mmdb_asn: str = "") -> None:
        self.enabled = enabled
        self.resolve_dns = resolve_dns
        self.results: Dict[str, GeoInfo] = {}
        self.home: Optional[GeoInfo] = None
        self.status = "idle"
        self._lock = threading.Lock()
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._pending: set[str] = set()
        self._stop = threading.Event()
        self._dirty = False

        self.provider = None
        if enabled:
            if mmdb:
                try:
                    self.provider = MmdbProvider(mmdb, mmdb_asn)
                except Exception as exc:             # noqa: BLE001
                    self.status = f"mmdb unavailable: {exc}"[:80]
                    self.provider = ChainProvider()
            else:
                self.provider = ChainProvider()

        self._load_cache()
        self._thread = threading.Thread(target=self._worker, daemon=True,
                                        name="netmonguru-enrich")
        self._thread.start()

    # -- cache ------------------------------------------------------------
    def _load_cache(self) -> None:
        path = cache_path()
        try:
            raw = json.loads(path.read_text())
        except Exception:                            # noqa: BLE001
            return
        now = time.time()
        for ip, entry in (raw.get("entries") or {}).items():
            if now - entry.get("ts", 0) > CACHE_TTL:
                continue
            self.results[ip] = GeoInfo(
                ip=ip, lat=entry.get("lat"), lon=entry.get("lon"),
                city=entry.get("city", ""), country=entry.get("country", ""),
                country_code=entry.get("cc", ""), org=entry.get("org", ""),
                asn=entry.get("asn", ""), hostname=entry.get("host", ""),
                source="cache")

    def save_cache(self) -> None:
        if not self._dirty:
            return
        path = cache_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            now = time.time()
            with self._lock:
                entries = {
                    ip: {"lat": g.lat, "lon": g.lon, "city": g.city,
                         "country": g.country, "cc": g.country_code,
                         "org": g.org, "asn": g.asn, "host": g.hostname,
                         "ts": now}
                    for ip, g in self.results.items()
                    if g.source != "local"}
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"entries": entries}))
            tmp.replace(path)
            self._dirty = False
        except Exception:                            # noqa: BLE001
            pass

    # -- public API --------------------------------------------------------
    def submit(self, ips: Iterable[str]) -> None:
        for ip in ips:
            if not ip:
                continue
            with self._lock:
                if ip in self.results or ip in self._pending:
                    continue
                if not is_routable(ip):
                    self.results[ip] = _local_info(ip)
                    continue
                self._pending.add(ip)
            self._queue.put(ip)

    def get(self, ip: str) -> Optional[GeoInfo]:
        with self._lock:
            return self.results.get(ip)

    def snapshot(self) -> Dict[str, GeoInfo]:
        with self._lock:
            return dict(self.results)

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._pending)

    def stop(self) -> None:
        self._stop.set()
        self.save_cache()

    # -- worker ------------------------------------------------------------
    def _drain(self, first: str) -> List[str]:
        batch = [first]
        deadline = time.monotonic() + 0.6
        while len(batch) < BATCH_SIZE and time.monotonic() < deadline:
            try:
                batch.append(self._queue.get(timeout=0.15))
            except queue.Empty:
                break
        return batch

    def _worker(self) -> None:
        last_save = time.monotonic()
        if hasattr(self.provider, "lookup_self"):
            self.home = self.provider.lookup_self()
        while not self._stop.is_set():
            try:
                first = self._queue.get(timeout=0.5)
            except queue.Empty:
                if time.monotonic() - last_save > 20:
                    self.save_cache()
                    last_save = time.monotonic()
                continue
            batch = self._drain(first)
            found: Dict[str, GeoInfo] = {}
            if self.provider is not None:
                try:
                    self.status = f"resolving {len(batch)}"
                    found = self.provider.lookup(batch)
                    self.status = getattr(self.provider, "error", "") or "ok"
                except Exception as exc:             # noqa: BLE001
                    self.status = f"lookup failed: {exc}"[:80]
                    found = {}
            for ip in batch:
                info = found.get(ip) or GeoInfo(ip=ip, source="unresolved")
                if self.resolve_dns and not info.hostname:
                    info.hostname = _reverse_dns(ip)
                with self._lock:
                    self.results[ip] = info
                    self._pending.discard(ip)
            self._dirty = True


def _reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(1.5)
        return socket.gethostbyaddr(ip)[0]
    except Exception:                                # noqa: BLE001
        return ""
    finally:
        socket.setdefaulttimeout(None)
