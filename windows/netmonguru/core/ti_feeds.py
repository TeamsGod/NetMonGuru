"""Locally matched threat-intelligence feeds.

Every feed is downloaded as a whole, cached on disk and matched in memory, so
checking a connection against them never tells anybody which addresses this
machine talks to.  That is what makes it acceptable to run for *every* socket.

Severity
    ``malicious``   confirmed malware infrastructure (botnet C2, vetted IOC)
    ``suspicious``  hijacked / criminal networks and compromised hosts
    ``info``        worth knowing, not a verdict by itself (Tor exit)
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .util import give_back

USER_AGENT = "NetMonGuru-TI/1.3 (+local network monitor)"
REFRESH = 6 * 3600          # abuse.ch asks for >= 5 min; feeds move slowly
MIN_REFRESH = 600


@dataclass
class FeedHit:
    feed: str               # feed id
    label: str              # short text for the table: "C2 Emotet", "DROP"
    severity: str           # malicious | suspicious | info
    detail: str = ""        # one line for the report
    port: int = 0           # when the feed names a port


@dataclass
class FeedDef:
    ident: str
    title: str
    url: str
    fmt: str                # how to parse: see _PARSERS
    severity: str
    label: str
    needs_key: str = ""     # name of the API key that must be configured
    note: str = ""
    kind: str = "ip"        # ip | domain


FEEDS: List[FeedDef] = [
    FeedDef("feodo", "abuse.ch Feodo Tracker",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            "feodo_json", "malicious", "C2",
            note="botnet C2 servers seen in the last 30 days"),
    FeedDef("sslbl", "abuse.ch SSLBL",
            "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
            "sslbl_csv", "malicious", "C2-SSL",
            note="hosts presenting certificates used by malware C2"),
    FeedDef("threatfox", "abuse.ch ThreatFox (7 days)",
            "https://threatfox-api.abuse.ch/api/v1/",
            "threatfox_api", "malicious", "IOC", needs_key="abusech",
            note="vetted ip:port IOCs with malware family"),
    FeedDef("spamhaus", "Spamhaus DROP",
            "https://www.spamhaus.org/drop/drop.txt",
            "netlist", "suspicious", "DROP",
            note="hijacked / criminal netblocks - no legitimate traffic"),
    FeedDef("et", "Emerging Threats compromised",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "netlist", "suspicious", "COMPROMISED",
            note="hosts observed attacking others"),
    FeedDef("firehol", "FireHOL level 1",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/"
            "master/firehol_level1.netset",
            "netlist", "suspicious", "BLOCKLIST",
            note="aggregate of the most trusted blocklists"),
    FeedDef("urlhaus", "abuse.ch URLhaus (domains)",
            "https://urlhaus.abuse.ch/downloads/hostfile/",
            "hostfile", "malicious", "MALWARE-HOST", kind="domain",
            note="host currently serving malware"),
    FeedDef("threatfox_domains", "abuse.ch ThreatFox domains (7 days)",
            "https://threatfox-api.abuse.ch/api/v1/",
            "threatfox_domains", "malicious", "IOC", needs_key="abusech",
            kind="domain", note="vetted domain IOCs with malware family"),
    FeedDef("tor", "Tor exit nodes",
            "https://check.torproject.org/torbulkexitlist",
            "netlist", "info", "TOR",
            note="current Tor exit relays"),
]

SEVERITY_RANK = {"": 0, "clean": 0, "info": 1, "suspicious": 2, "malicious": 3}


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

@dataclass
class FeedData:
    ips: Dict[str, List[Tuple[int, str]]] = field(default_factory=dict)
    nets: List[Tuple[int, int, int, str]] = field(default_factory=list)
    # nets: (version, first, last, original) sorted by first
    domains: Dict[str, str] = field(default_factory=dict)   # name -> detail

    @property
    def size(self) -> int:
        return len(self.ips) + len(self.nets) + len(self.domains)

    def add(self, token: str, port: int = 0, detail: str = "") -> None:
        token = token.strip()
        if not token:
            return
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                if net.num_addresses == 1:
                    token = str(net.network_address)
                else:
                    # bogon space in aggregate lists is not threat intel
                    if net.is_private or net.is_loopback or net.is_multicast \
                            or net.is_reserved or net.is_link_local \
                            or net.prefixlen < 8:
                        return
                    self.nets.append((net.version, int(net.network_address),
                                      int(net.broadcast_address), str(net)))
                    return
            ip = ipaddress.ip_address(token)
        except ValueError:
            return
        self.ips.setdefault(str(ip), []).append((port, detail))

    def finish(self) -> "FeedData":
        self.nets.sort()
        return self

    def find(self, ip: str) -> Optional[Tuple[List[Tuple[int, str]], str]]:
        exact = self.ips.get(ip)
        if exact is not None:
            return exact, ""
        if not self.nets:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        value, version = int(addr), addr.version
        for ver, first, last, text in self.nets:
            if ver == version and first <= value <= last:
                return [(0, "")], text
        return None


def _parse_netlist(raw: bytes) -> FeedData:
    data = FeedData()
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if line:
            data.add(line.split()[0])
    return data.finish()


def _parse_feodo(raw: bytes) -> FeedData:
    data = FeedData()
    for row in json.loads(raw.decode("utf-8", "replace")) or []:
        bits = [str(row.get("malware") or "").strip(),
                f"status {row.get('status')}" if row.get("status") else "",
                f"last online {row.get('last_online')}"
                if row.get("last_online") else ""]
        data.add(str(row.get("ip_address") or ""),
                 int(row.get("port") or 0),
                 " · ".join(b for b in bits if b))
    return data.finish()


def _parse_sslbl(raw: bytes) -> FeedData:
    data = FeedData()
    text = "\n".join(l for l in raw.decode("utf-8", "replace").splitlines()
                     if l and not l.startswith("#"))
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 3:
            try:
                port = int(row[2])
            except ValueError:
                port = 0
            data.add(row[1], port, f"first seen {row[0]}")
    return data.finish()


def _parse_threatfox(raw: bytes) -> FeedData:
    data = FeedData()
    body = json.loads(raw.decode("utf-8", "replace"))
    if body.get("query_status") != "ok":
        raise ValueError(f"threatfox: {body.get('query_status')}")
    for row in body.get("data") or []:
        if row.get("ioc_type") != "ip:port":
            continue
        ioc = str(row.get("ioc") or "")
        host, _, port = ioc.rpartition(":")
        bits = [str(row.get("malware_printable") or ""),
                str(row.get("threat_type") or ""),
                f"confidence {row.get('confidence_level')}%"
                if row.get("confidence_level") is not None else ""]
        try:
            data.add(host.strip("[]"), int(port),
                     " · ".join(b for b in bits if b))
        except ValueError:
            continue
    return data.finish()


def _parse_hostfile(raw: bytes) -> FeedData:
    """``127.0.0.1<TAB>bad.example`` (or a bare name) per line."""
    data = FeedData()
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name = line.split()[-1].lower().rstrip(".")
        if "." in name and name not in ("localhost", "0.0.0.0") \
                and not name.replace(".", "").isdigit():
            data.domains[name] = ""
    return data


def _parse_threatfox_domains(raw: bytes) -> FeedData:
    data = FeedData()
    body = json.loads(raw.decode("utf-8", "replace"))
    if body.get("query_status") != "ok":
        raise ValueError(f"threatfox: {body.get('query_status')}")
    for row in body.get("data") or []:
        if row.get("ioc_type") != "domain":
            continue
        bits = [str(row.get("malware_printable") or ""),
                str(row.get("threat_type") or ""),
                f"confidence {row.get('confidence_level')}%"
                if row.get("confidence_level") is not None else ""]
        name = str(row.get("ioc") or "").lower().rstrip(".")
        if name:
            data.domains[name] = " · ".join(b for b in bits if b)
    return data


# ---------------------------------------------------------------------------
# algorithmically generated names
# ---------------------------------------------------------------------------

_VOWELS = set("aeiouy")


def _entropy(text: str) -> float:
    import math
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_generated(name: str) -> bool:
    """Cheap DGA heuristic on the registrable label only - CDNs put random
    strings in *sub*domains all the time, malware puts them in the domain."""
    parts = name.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return False
    two_level = {"co", "com", "org", "net", "gov", "edu", "ac"}
    label = parts[-3] if len(parts) >= 3 and parts[-2] in two_level \
        else parts[-2]
    if len(label) < 12 or "-" in label:
        return False
    letters = [ch for ch in label if ch.isalpha()]
    digits = sum(ch.isdigit() for ch in label)
    if not letters:
        return digits >= 12
    vowels = sum(ch in _VOWELS for ch in letters) / len(letters)
    return _entropy(label) >= 3.5 and (vowels < 0.28 or digits / len(label)
                                       > 0.3)


_PARSERS: Dict[str, Callable[[bytes], FeedData]] = {
    "hostfile": _parse_hostfile,
    "threatfox_domains": _parse_threatfox_domains,
    "netlist": _parse_netlist,
    "feodo_json": _parse_feodo,
    "sslbl_csv": _parse_sslbl,
    "threatfox_api": _parse_threatfox,
}


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------

@dataclass
class FeedState:
    definition: FeedDef
    data: FeedData = field(default_factory=FeedData)
    fetched: float = 0.0
    status: str = "not loaded"
    error: str = ""


Fetcher = Callable[[str, Dict[str, str], Optional[bytes]], bytes]


def default_fetch(url: str, headers: Dict[str, str],
                  body: Optional[bytes] = None) -> bytes:
    import urllib.request

    req = urllib.request.Request(
        url, data=body, headers={"User-Agent": USER_AGENT, **headers})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return resp.read(64 * 1024 * 1024)


def feed_dir() -> Path:
    from .win import cache_dir
    return cache_dir() / "feeds"


class FeedStore:
    def __init__(self, keys: Optional[Dict[str, str]] = None,
                 directory: Optional[Path] = None,
                 fetch: Fetcher = default_fetch,
                 refresh: int = REFRESH) -> None:
        self.keys = keys or {}
        self.dir = Path(directory) if directory else feed_dir()
        self.fetch = fetch
        self.refresh = max(MIN_REFRESH, refresh)
        self.feeds: Dict[str, FeedState] = {
            d.ident: FeedState(d) for d in FEEDS}
        self.generation = 0            # bumped whenever data changes
        self._lock = threading.Lock()
        self.load_cached()

    # -- loading -------------------------------------------------------------
    def _path(self, ident: str) -> Path:
        return self.dir / f"{ident}.raw"

    def load_cached(self) -> None:
        for ident, st in self.feeds.items():
            path = self._path(ident)
            try:
                if path.exists():
                    st.data = _PARSERS[st.definition.fmt](path.read_bytes())
                    st.fetched = path.stat().st_mtime
                    st.status = "cached"
                    self.generation += 1
            except Exception as exc:                    # noqa: BLE001
                st.status, st.error = "error", f"cache: {exc}"

    def due(self, now: Optional[float] = None) -> List[str]:
        now = time.time() if now is None else now
        return [i for i, st in self.feeds.items()
                if now - st.fetched >= self.refresh
                and self._usable(st.definition)]

    def _usable(self, d: FeedDef) -> bool:
        return not d.needs_key or bool(self.keys.get(d.needs_key))

    def update(self, ident: str) -> bool:
        st = self.feeds[ident]
        d = st.definition
        if not self._usable(d):
            st.status = f"needs {d.needs_key} key"
            return False
        try:
            if d.fmt in ("threatfox_api", "threatfox_domains"):
                raw = self.fetch(d.url, {"Auth-Key": self.keys[d.needs_key],
                                         "Content-Type": "application/json"},
                                 json.dumps({"query": "get_iocs",
                                             "days": 7}).encode())
            else:
                raw = self.fetch(d.url, {}, None)
            data = _PARSERS[d.fmt](raw)
            if not data.size and d.ident not in ("feodo",):
                # an empty download is far more likely an error page
                raise ValueError("feed came back empty")
        except Exception as exc:                        # noqa: BLE001
            st.error = str(exc)[:120]
            st.status = "error" if not st.data.size else "stale"
            # do not hammer a failing feed: retry after MIN_REFRESH
            st.fetched = max(st.fetched,
                             time.time() - self.refresh + MIN_REFRESH)
            return False
        with self._lock:
            st.data, st.fetched = data, time.time()
            st.status, st.error = "ok", ""
            self.generation += 1
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            tmp = self._path(ident).with_suffix(".tmp")
            tmp.write_bytes(raw)
            tmp.replace(self._path(ident))
            give_back(self._path(ident))
        except Exception:                               # noqa: BLE001
            pass
        return True

    def update_due(self, force: bool = False) -> int:
        idents = list(self.feeds) if force else self.due()
        return sum(1 for i in idents if self.update(i))

    # -- lookup --------------------------------------------------------------
    def lookup_domain(self, name: str, dga: bool = True
                      ) -> Optional[FeedHit]:
        """Exact name or any parent domain listed in a domain feed."""
        name = (name or "").lower().rstrip(".")
        if not name or "." not in name:
            return None
        parts = name.split(".")
        candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)]
        for st in self.feeds.values():
            if st.definition.kind != "domain" or not st.data.domains:
                continue
            for cand in candidates:
                detail = st.data.domains.get(cand)
                if detail is None:
                    continue
                d = st.definition
                family = detail.split(" · ")[0] if detail else ""
                label = f"{d.label} {family}".strip()
                text = detail or d.note
                if cand != name:
                    text = f"parent {cand} listed — {text}"
                return FeedHit(d.ident, label, d.severity, text)
        if dga and looks_generated(name):
            return FeedHit("dga", "DGA?", "info",
                           "name looks machine-generated (heuristic)")
        return None

    def lookup(self, ip: str, port: int = 0) -> List[FeedHit]:
        hits: List[FeedHit] = []
        for st in self.feeds.values():
            if st.definition.kind != "ip":
                continue
            found = st.data.find(ip)
            if found is None:
                continue
            entries, net = found
            d = st.definition
            # prefer the entry naming the port we actually talk to
            entry = next((e for e in entries if port and e[0] == port),
                         entries[0])
            family = entry[1].split(" · ")[0] if entry[1] else ""
            label = d.label
            if family and d.ident in ("feodo", "threatfox"):
                label = f"{d.label} {family}"
            detail = entry[1] or d.note
            if net:
                detail = f"in {net} — {d.note}"
            severity = d.severity
            if entry[0] and port and entry[0] != port \
                    and severity == "malicious":
                detail += f" (listed for port {entry[0]}, not {port})"
            hits.append(FeedHit(d.ident, label, severity, detail, entry[0]))
        hits.sort(key=lambda h: -SEVERITY_RANK[h.severity])
        return hits

    def summary(self) -> List[Tuple[str, str, int, float, str]]:
        return [(st.definition.title, st.status, st.data.size, st.fetched,
                 st.error) for st in self.feeds.values()]
