"""Core data types shared by collectors and the UI."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------

#: TCP states we consider "an actual end-to-end conversation".
ACTIVE_TCP_STATES = {"ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT_1", "FIN_WAIT_2",
                     "LAST_ACK", "CLOSING", "TIME_WAIT", "SYN_SENT",
                     "SYN_RECV", "SYN_RECEIVED"}


@dataclass(slots=True)
class Connection:
    """A single socket as reported by lsof / psutil."""

    proto: str                      # TCP / UDP
    family: str                     # IPv4 / IPv6
    laddr: str = ""
    lport: int = 0
    raddr: str = ""
    rport: int = 0
    state: str = ""                 # ESTABLISHED, LISTEN, ... ("" for UDP)
    pid: Optional[int] = None
    pname: str = ""

    # ---- derived ---------------------------------------------------------
    @property
    def key(self) -> str:
        return (f"{self.proto}/{self.family}/{self.laddr}:{self.lport}/"
                f"{self.raddr}:{self.rport}/{self.pid}")

    @property
    def is_listening(self) -> bool:
        return self.state == "LISTEN" or (not self.raddr and self.proto == "UDP")

    @property
    def is_established(self) -> bool:
        return bool(self.raddr) and self.state in ("ESTABLISHED", "")

    @property
    def local(self) -> str:
        return _fmt_endpoint(self.laddr, self.lport)

    @property
    def remote(self) -> str:
        return _fmt_endpoint(self.raddr, self.rport)


def _fmt_endpoint(addr: str, port: int) -> str:
    if not addr:
        return "-"
    if ":" in addr and not addr.startswith("["):
        addr = f"[{addr}]"
    return f"{addr}:{port}" if port else addr


def classify_address(addr: str) -> str:
    """Return one of: ``public``, ``private``, ``loopback``, ``multicast``,
    ``wildcard``, ``unknown``."""
    if not addr or addr in ("*", "0.0.0.0", "::"):
        return "wildcard"
    try:
        ip = ipaddress.ip_address(addr.strip("[]"))
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
        return "private"
    return "public"


def is_routable(addr: str) -> bool:
    """True when the address is worth geolocating."""
    return classify_address(addr) == "public"


# ---------------------------------------------------------------------------
# Geo / ownership metadata
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class GeoInfo:
    ip: str
    lat: Optional[float] = None
    lon: Optional[float] = None
    city: str = ""
    country: str = ""
    country_code: str = ""
    org: str = ""
    asn: str = ""
    hostname: str = ""
    source: str = ""                # api / mmdb / cache / local

    @property
    def located(self) -> bool:
        return self.lat is not None and self.lon is not None

    @property
    def label(self) -> str:
        bits = [b for b in (self.city, self.country) if b]
        return ", ".join(bits) if bits else "-"


# ---------------------------------------------------------------------------
# Bandwidth
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class NicSample:
    name: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    up_rate: float = 0.0            # bytes/s
    down_rate: float = 0.0          # bytes/s
    up_history: List[float] = field(default_factory=list)
    down_history: List[float] = field(default_factory=list)


@dataclass(slots=True)
class ProcNet:
    """Per-process throughput (macOS ``nettop``)."""

    pid: Optional[int]
    name: str
    bytes_in: int = 0
    bytes_out: int = 0
    in_rate: float = 0.0
    out_rate: float = 0.0
    conns: int = 0


# ---------------------------------------------------------------------------
# Snapshot handed to the UI
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Snapshot:
    connections: List[Connection] = field(default_factory=list)
    nics: Dict[str, NicSample] = field(default_factory=dict)
    procs: Dict[str, ProcNet] = field(default_factory=dict)
    geo: Dict[str, GeoInfo] = field(default_factory=dict)
    dns_names: Dict[str, str] = field(default_factory=dict)
    total_up: float = 0.0
    total_down: float = 0.0
    up_history: List[float] = field(default_factory=list)
    down_history: List[float] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    elevated: bool = False
    backend: str = ""
    ts: float = 0.0

    def counts(self) -> Tuple[int, int, int, int]:
        tcp = sum(1 for c in self.connections if c.proto == "TCP")
        udp = sum(1 for c in self.connections if c.proto == "UDP")
        est = sum(1 for c in self.connections if c.state == "ESTABLISHED")
        lis = sum(1 for c in self.connections if c.is_listening)
        return tcp, udp, est, lis
