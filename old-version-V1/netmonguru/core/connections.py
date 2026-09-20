"""Socket table collectors.

macOS does not let an unprivileged process read another process' file table,
so we combine two sources:

* ``lsof -i``   - gives PID / process name, but only for processes we may
  inspect (everything when run with ``sudo``).
* ``netstat -an`` - gives *every* socket on the system, but no ownership.

Merging them means the connection list is always complete; rows we could not
attribute to a process simply show ``?``.  ``psutil`` is used as a fallback if
``lsof`` is unavailable.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from .models import Connection

LSOF_TIMEOUT = 8
NETSTAT_TIMEOUT = 8

_STATE_ALIASES = {
    "SYN_RECEIVED": "SYN_RECV",
    "CLOSE_WAIT": "CLOSE_WAIT",
    "ESTABLISHED": "ESTABLISHED",
}


class CollectorError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], timeout: int) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, check=False)
    except FileNotFoundError as exc:                       # pragma: no cover
        raise CollectorError(f"{cmd[0]} not found") from exc
    except subprocess.TimeoutExpired as exc:               # pragma: no cover
        raise CollectorError(f"{cmd[0]} timed out") from exc
    # lsof exits 1 when some sockets could not be read - the output is still
    # usable, so only treat "no output at all" as a failure.
    if not res.stdout and res.returncode != 0:
        raise CollectorError((res.stderr or "").strip()[:200] or
                             f"{cmd[0]} failed ({res.returncode})")
    return res.stdout


def _split_hostport(text: str) -> Tuple[str, int]:
    """Split ``1.2.3.4:443`` / ``[::1]:80`` / ``*:*`` into (addr, port)."""
    text = text.strip()
    if not text or text in ("*:*", "*"):
        return "", 0
    if text.startswith("["):
        host, _, port = text.partition("]")
        host = host[1:]
        port = port.lstrip(":")
    else:
        host, _, port = text.rpartition(":")
        if not host:                       # bare port or bare host
            host, port = text, ""
    host = "" if host == "*" else host
    host = host.split("%", 1)[0]           # drop scope id (fe80::1%en0)
    try:
        port_i = int(port)
    except ValueError:
        port_i = 0
    return host, port_i


def _split_dotted(text: str) -> Tuple[str, int]:
    """netstat style ``192.168.1.10.52341`` / ``fe80::1%en0.5353``."""
    text = text.strip()
    if not text or text == "*.*":
        return "", 0
    host, _, port = text.rpartition(".")
    host = "" if host in ("*", "") else host
    host = host.split("%", 1)[0]
    try:
        port_i = int(port)
    except ValueError:
        port_i = 0
    return host, port_i


def _norm_state(state: str) -> str:
    state = (state or "").strip().upper()
    return _STATE_ALIASES.get(state, state)


# ---------------------------------------------------------------------------
# lsof
# ---------------------------------------------------------------------------

def parse_lsof(output: str) -> List[Connection]:
    """Parse ``lsof -nP -i -w +c 0 -F pcftPnT`` field output."""
    conns: List[Connection] = []
    pid: Optional[int] = None
    pname = ""
    cur: Optional[Dict[str, str]] = None

    def flush() -> None:
        nonlocal cur
        if not cur:
            cur = None
            return
        proto = cur.get("P", "").upper()
        if proto not in ("TCP", "UDP"):
            cur = None
            return
        name = cur.get("n", "")
        local_s, _, remote_s = name.partition("->")
        laddr, lport = _split_hostport(local_s)
        raddr, rport = _split_hostport(remote_s)
        family = "IPv6" if cur.get("t", "").upper() == "IPV6" else "IPv4"
        conns.append(Connection(
            proto=proto, family=family, laddr=laddr, lport=lport,
            raddr=raddr, rport=rport, state=_norm_state(cur.get("TST", "")),
            pid=pid, pname=pname or "?"))
        cur = None

    for line in output.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            flush()
            try:
                pid = int(value)
            except ValueError:
                pid = None
        elif tag == "c":
            pname = value
        elif tag == "f":
            flush()
            cur = {}
        elif cur is not None:
            if tag == "T":
                sub, _, val = value.partition("=")
                cur["T" + sub] = val
            else:
                cur[tag] = value
    flush()
    return conns


def collect_lsof() -> List[Connection]:
    out = _run(["lsof", "-nP", "-i", "-w", "+c", "0", "-F", "pcftPnT"],
               LSOF_TIMEOUT)
    return parse_lsof(out)


# ---------------------------------------------------------------------------
# netstat
# ---------------------------------------------------------------------------

_NETSTAT_RE = re.compile(
    r"^(tcp|udp)(4|6|46)?\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s*$")


def parse_netstat(output: str) -> List[Connection]:
    conns: List[Connection] = []
    for line in output.splitlines():
        m = _NETSTAT_RE.match(line.strip())
        if not m:
            continue
        proto, fam, local_s, remote_s, state = m.groups()
        laddr, lport = _split_dotted(local_s)
        raddr, rport = _split_dotted(remote_s)
        conns.append(Connection(
            proto=proto.upper(),
            family="IPv6" if fam == "6" else "IPv4",
            laddr=laddr, lport=lport, raddr=raddr, rport=rport,
            state=_norm_state(state or ""), pid=None, pname="?"))
    return conns


def collect_netstat() -> List[Connection]:
    return parse_netstat(_run(["netstat", "-an"], NETSTAT_TIMEOUT))


# ---------------------------------------------------------------------------
# psutil fallback
# ---------------------------------------------------------------------------

def collect_psutil() -> List[Connection]:
    import psutil                                   # local import: optional

    conns: List[Connection] = []
    names: Dict[int, str] = {}
    for c in psutil.net_connections(kind="inet"):
        laddr = getattr(c.laddr, "ip", "") if c.laddr else ""
        lport = getattr(c.laddr, "port", 0) if c.laddr else 0
        raddr = getattr(c.raddr, "ip", "") if c.raddr else ""
        rport = getattr(c.raddr, "port", 0) if c.raddr else 0
        proto = "TCP" if c.type == 1 else "UDP"       # SOCK_STREAM == 1
        family = "IPv6" if int(c.family) == 30 or ":" in laddr else "IPv4"
        pname = ""
        if c.pid:
            if c.pid not in names:
                try:
                    names[c.pid] = psutil.Process(c.pid).name()
                except Exception:                     # noqa: BLE001
                    names[c.pid] = "?"
            pname = names[c.pid]
        state = "" if proto == "UDP" else _norm_state(
            "" if c.status == "NONE" else c.status)
        conns.append(Connection(proto=proto, family=family, laddr=laddr,
                                lport=lport, raddr=raddr, rport=rport,
                                state=state, pid=c.pid, pname=pname or "?"))
    return conns


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------

def _sig(c: Connection) -> Tuple:
    return (c.proto, c.laddr, c.lport, c.raddr, c.rport)


def merge(primary: List[Connection],
          secondary: List[Connection]) -> List[Connection]:
    """Keep every socket; prefer rows that carry process ownership."""
    out: Dict[Tuple, Connection] = {}
    for c in primary:
        out[_sig(c)] = c
    for c in secondary:
        sig = _sig(c)
        if sig in out:
            existing = out[sig]
            if not existing.state and c.state:
                existing.state = c.state
        else:
            out[sig] = c
    return list(out.values())


class ConnectionCollector:
    """Chooses the best available backend and caches that decision."""

    def __init__(self, use_netstat: bool = True) -> None:
        self.use_netstat = use_netstat
        self.backend = ""
        self.errors: List[str] = []
        self._have_lsof = shutil.which("lsof") is not None
        self._have_netstat = shutil.which("netstat") is not None

    @property
    def elevated(self) -> bool:
        try:
            return os.geteuid() == 0
        except AttributeError:                        # pragma: no cover
            return False

    def collect(self) -> List[Connection]:
        self.errors = []
        primary: List[Connection] = []
        backend = []

        if self._have_lsof:
            try:
                primary = collect_lsof()
                backend.append("lsof")
            except CollectorError as exc:
                self.errors.append(f"lsof: {exc}")

        if not primary:
            try:
                primary = collect_psutil()
                backend.append("psutil")
            except Exception as exc:                  # noqa: BLE001
                self.errors.append(f"psutil: {exc}")

        secondary: List[Connection] = []
        if self.use_netstat and self._have_netstat:
            try:
                secondary = collect_netstat()
                backend.append("netstat")
            except CollectorError as exc:
                self.errors.append(f"netstat: {exc}")

        self.backend = "+".join(backend) or "none"
        return merge(primary, secondary)
