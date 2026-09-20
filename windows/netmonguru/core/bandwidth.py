"""Per-interface bandwidth sampling (psutil) and per-process throughput
(macOS ``nettop``)."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from .models import FlowNet, NicSample, ProcNet

HISTORY = 240          # samples kept for the graphs

# Interfaces that are noise in a network monitor.
_SKIP_PREFIXES = ("lo", "gif", "stf", "ap", "awdl", "llw", "bridge",
                  "p2p", "utun.dummy")


class BandwidthCollector:
    """Turns cumulative counters into per-second rates plus history."""

    def __init__(self, hide_idle: bool = True) -> None:
        self.hide_idle = hide_idle
        self._prev: Dict[str, Tuple[int, int, int, int]] = {}
        self._prev_ts: Optional[float] = None
        self._hist_up: Dict[str, Deque[float]] = {}
        self._hist_down: Dict[str, Deque[float]] = {}
        self.total_up_hist: Deque[float] = deque([0.0] * HISTORY, maxlen=HISTORY)
        self.total_down_hist: Deque[float] = deque([0.0] * HISTORY, maxlen=HISTORY)

    @staticmethod
    def _interesting(name: str) -> bool:
        return not name.startswith(_SKIP_PREFIXES)

    def collect(self) -> Dict[str, NicSample]:
        import psutil

        now = time.monotonic()
        counters = psutil.net_io_counters(pernic=True)
        dt = (now - self._prev_ts) if self._prev_ts else 0.0
        out: Dict[str, NicSample] = {}
        total_up = total_down = 0.0

        for name, c in counters.items():
            if not self._interesting(name):
                continue
            cur = (c.bytes_sent, c.bytes_recv, c.packets_sent, c.packets_recv)
            up = down = 0.0
            if dt > 0 and name in self._prev:
                p = self._prev[name]
                up = max(0, cur[0] - p[0]) / dt
                down = max(0, cur[1] - p[1]) / dt
            self._prev[name] = cur

            hu = self._hist_up.setdefault(
                name, deque([0.0] * HISTORY, maxlen=HISTORY))
            hd = self._hist_down.setdefault(
                name, deque([0.0] * HISTORY, maxlen=HISTORY))
            hu.append(up)
            hd.append(down)

            sample = NicSample(name=name, bytes_sent=cur[0], bytes_recv=cur[1],
                               packets_sent=cur[2], packets_recv=cur[3],
                               up_rate=up, down_rate=down,
                               up_history=list(hu), down_history=list(hd))
            total_up += up
            total_down += down
            if self.hide_idle and cur[0] == 0 and cur[1] == 0:
                continue
            out[name] = sample

        self._prev_ts = now
        self.total_up_hist.append(total_up)
        self.total_down_hist.append(total_down)
        return out

    @property
    def totals(self) -> Tuple[float, float]:
        return self.total_up_hist[-1], self.total_down_hist[-1]


# ---------------------------------------------------------------------------
# nettop - per process and per connection throughput on macOS
# ---------------------------------------------------------------------------

_NETTOP_ROW = re.compile(r"^(?P<name>.+?)\.(?P<pid>\d+)$")
_NETTOP_TIME = re.compile(r"^\d{1,2}:\d{2}:\d{2}")
_NETTOP_FLOW = re.compile(r"^(?P<proto>tcp|udp)(?P<ver>[46])\s+"
                          r"(?P<local>\S+?)<->(?P<remote>\S+)$", re.I)

ProcTuple = Tuple[Optional[int], str, int, int]


def _endpoint(text: str) -> Tuple[str, int]:
    """``1.2.3.4:443`` / ``2a00::1.443`` / ``fe80::1%en0.5353`` / ``*:*``
    (nettop writes IPv6 ports after a dot)."""
    text = text.strip()
    sep = "." if text.count(":") > 1 else ":"
    host, _, port = text.rpartition(sep)
    if not host:
        host, port = text, ""
    host = host.strip("[]").split("%")[0]
    if host in ("*", ""):
        host = ""
    try:
        return host, int(port)
    except ValueError:
        return host, 0


def flow_key(proto: str, laddr: str, lport: int, raddr: str, rport: int
             ) -> str:
    return f"{proto.upper()}|{laddr}|{lport}|{raddr}|{rport}"


def parse_nettop_full(output: str
                      ) -> Tuple[Dict[str, ProcTuple], Dict[str, FlowNet]]:
    """Parse ``nettop -L 1 -x -n -J bytes_in,bytes_out`` CSV.

    Works for both layouts seen in the wild - the label in the first column,
    or (current macOS) a timestamp first and the label second - and for both
    ``-P`` (process rows only) and the full listing, where every process row
    is followed by the rows of its connections::

        time,,bytes_in,bytes_out,
        16:41:16.73,firefox.501,1048576,262144,
        16:41:16.73,tcp4 192.168.1.24:51344<->142.250.203.110:443,1040000,260000,

    Returns ``(processes, flows)``; byte counters are cumulative.
    """
    procs: Dict[str, ProcTuple] = {}
    flows: Dict[str, FlowNet] = {}
    idx_in = idx_out = None
    owner: Tuple[Optional[int], str] = (None, "")
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        lowered = [p.lower() for p in parts]
        if "bytes_in" in lowered and "bytes_out" in lowered:
            idx_in = lowered.index("bytes_in")
            idx_out = lowered.index("bytes_out")
            continue
        if idx_in is None or idx_out is None:
            continue
        if len(parts) <= max(idx_in, idx_out):
            continue
        label = parts[0]
        if _NETTOP_TIME.match(label) and len(parts) > 1:
            label = parts[1]
        if not label or label.lower().startswith("time"):
            continue
        try:
            b_in = int(parts[idx_in] or 0)
            b_out = int(parts[idx_out] or 0)
        except ValueError:
            continue

        f = _NETTOP_FLOW.match(label)
        if f:
            proto = f.group("proto").upper()
            laddr, lport = _endpoint(f.group("local"))
            raddr, rport = _endpoint(f.group("remote"))
            key = flow_key(proto, laddr, lport, raddr, rport)
            flows[key] = FlowNet(key=key, proto=proto,
                                 family="IPv6" if f.group("ver") == "6"
                                 else "IPv4",
                                 laddr=laddr, lport=lport, raddr=raddr,
                                 rport=rport, pid=owner[0], pname=owner[1],
                                 bytes_in=b_in, bytes_out=b_out)
            continue
        m = _NETTOP_ROW.match(label)
        if m:
            name, pid = m.group("name"), int(m.group("pid"))
        else:
            name, pid = label, None
        owner = (pid, name)
        procs[label] = (pid, name, b_in, b_out)
    return procs, flows


def parse_nettop(output: str) -> Dict[str, ProcTuple]:
    """Process rows only: ``{key: (pid, name, bytes_in, bytes_out)}``."""
    return parse_nettop_full(output)[0]


class _Rates:
    """Cumulative counters -> rates + rolling history, per key."""

    def __init__(self) -> None:
        self.prev: Dict[str, Tuple[int, int]] = {}
        self.down: Dict[str, Deque[float]] = {}
        self.up: Dict[str, Deque[float]] = {}

    def feed(self, key: str, b_in: int, b_out: int, dt: float
             ) -> Tuple[float, float]:
        r_in = r_out = 0.0
        if dt > 0 and key in self.prev:
            p_in, p_out = self.prev[key]
            r_in = max(0, b_in - p_in) / dt
            r_out = max(0, b_out - p_out) / dt
        self.prev[key] = (b_in, b_out)
        hd = self.down.get(key)
        if hd is None:
            hd = self.down[key] = deque(maxlen=HISTORY)
            self.up[key] = deque(maxlen=HISTORY)
        hd.append(r_in)
        self.up[key].append(r_out)
        return r_in, r_out

    def prune(self, live) -> None:
        for key in [k for k in self.prev if k not in live]:
            self.prev.pop(key, None)
            self.down.pop(key, None)
            self.up.pop(key, None)

    def history(self, key: str) -> Tuple[List[float], List[float]]:
        for _ in range(3):                # the sampler thread may be appending
            try:
                return list(self.down.get(key, ())), list(self.up.get(key, ()))
            except RuntimeError:
                continue
        return [], []


class ProcessNetCollector:
    """Samples ``nettop`` and derives per-process and per-connection rates
    (plus a rolling history of each) between our own runs."""

    def __init__(self, enabled: bool = True) -> None:
        self.available = shutil.which("nettop") is not None
        self.enabled = enabled and self.available
        self.error = ""
        self.flows: Dict[str, FlowNet] = {}
        self._proc = _Rates()
        self._flow = _Rates()
        self._prev_ts: Optional[float] = None
        self._per_process_only = False

    def _nettop(self) -> str:
        cmd = ["nettop", "-L", "1", "-x", "-n", "-J", "bytes_in,bytes_out"]
        if self._per_process_only:
            cmd.insert(1, "-P")
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                             check=False)
        if not res.stdout.strip():
            raise RuntimeError((res.stderr or "nettop returned no data")
                               .strip()[:160])
        return res.stdout

    def collect(self) -> Dict[str, ProcNet]:
        if not self.enabled:
            return {}
        try:
            rows, flows = parse_nettop_full(self._nettop())
            if not rows and not self._per_process_only:
                # unexpected full-listing layout: keep at least per-process
                self._per_process_only = True
                rows, flows = parse_nettop_full(self._nettop())
        except Exception as exc:                       # noqa: BLE001
            self.error = str(exc)[:160]
            self.enabled = False
            return {}
        return self.ingest(rows, flows)

    def ingest(self, rows: Dict[str, ProcTuple], flows: Dict[str, FlowNet],
               now: Optional[float] = None) -> Dict[str, ProcNet]:
        now = time.monotonic() if now is None else now
        dt = (now - self._prev_ts) if self._prev_ts else 0.0
        out: Dict[str, ProcNet] = {}
        for key, (pid, name, b_in, b_out) in rows.items():
            r_in, r_out = self._proc.feed(key, b_in, b_out, dt)
            out[key] = ProcNet(pid=pid, name=name, bytes_in=b_in,
                               bytes_out=b_out, in_rate=r_in, out_rate=r_out)
        for key, f in flows.items():
            f.in_rate, f.out_rate = self._flow.feed(key, f.bytes_in,
                                                    f.bytes_out, dt)
        self._proc.prune(rows)
        self._flow.prune(flows)
        self.flows = flows
        self._prev_ts = now
        return out

    def proc_history(self, key: str) -> Tuple[List[float], List[float]]:
        return self._proc.history(key)

    def flow_history(self, key: str) -> Tuple[List[float], List[float]]:
        return self._flow.history(key)


class WindowsNetCollector(ProcessNetCollector):
    """Per-connection TCP byte counters from the kernel's extended statistics
    (``GetPerTcpConnectionEStats``), summed per owning process.

    Needs an elevated prompt.  UDP carries no such counters, so UDP traffic is
    not attributed (the per-interface totals still include it).
    """

    def __init__(self, enabled: bool = True) -> None:
        super().__init__(enabled=False)
        from .win import TcpEStats

        self._estats = TcpEStats()
        self.available = self._estats.available
        self.enabled = enabled and self.available
        self.error = self._estats.error
        self._names: Dict[int, str] = {}

    def collect_for(self, connections, interval: float = 2.0
                    ) -> Dict[str, ProcNet]:
        if not self.enabled:
            return {}
        rows: Dict[str, ProcTuple] = {}
        flows: Dict[str, FlowNet] = {}
        live = []
        for c in connections:
            if c.proto != "TCP" or not c.raddr or c.state in ("LISTEN", ""):
                continue
            live.append((c.laddr, c.lport, c.raddr, c.rport))
            counters = self._estats.read(c.laddr, c.lport, c.raddr, c.rport)
            if counters is None:
                if self._estats.denied:
                    self.error = self._estats.error
                    self.enabled = False
                    return {}
                continue
            b_in, b_out = counters
            key = flow_key(c.proto, c.laddr, c.lport, c.raddr, c.rport)
            flows[key] = FlowNet(key=key, proto=c.proto, family=c.family,
                                 laddr=c.laddr, lport=c.lport, raddr=c.raddr,
                                 rport=c.rport, pid=c.pid, pname=c.pname,
                                 bytes_in=b_in, bytes_out=b_out)
        self._estats.forget(live)
        return self.ingest_flows(flows)

    def ingest_flows(self, flows: Dict[str, FlowNet],
                     now: Optional[float] = None) -> Dict[str, ProcNet]:
        """Process totals are derived from *rates* of the flows, not from
        their counters: a closed connection takes its counter with it, which
        would otherwise look like a huge negative jump for the process."""
        now = time.monotonic() if now is None else now
        dt = (now - self._prev_ts) if self._prev_ts else 0.0
        out: Dict[str, ProcNet] = {}
        for key, f in flows.items():
            f.in_rate, f.out_rate = self._flow.feed(key, f.bytes_in,
                                                    f.bytes_out, dt)
            label = f"{f.pname or '?'}.{f.pid if f.pid is not None else 0}"
            p = out.get(label)
            if p is None:
                p = out[label] = ProcNet(pid=f.pid, name=f.pname or "?")
            p.in_rate += f.in_rate
            p.out_rate += f.out_rate
            p.bytes_in += f.bytes_in
            p.bytes_out += f.bytes_out
        for label, p in out.items():
            hd = self._proc.down.get(label)
            if hd is None:
                hd = self._proc.down[label] = deque(maxlen=HISTORY)
                self._proc.up[label] = deque(maxlen=HISTORY)
            hd.append(p.in_rate)
            self._proc.up[label].append(p.out_rate)
            self._proc.prev[label] = (p.bytes_in, p.bytes_out)
        self._proc.prune(out)
        self._flow.prune(flows)
        self.flows = flows
        self._prev_ts = now
        return out


class DemoNetCollector(ProcessNetCollector):
    """Synthetic per-process / per-connection traffic for ``--demo`` and the
    test-suite: a random walk per socket, summed per owning process."""

    def __init__(self) -> None:
        super().__init__(enabled=False)
        self.available = self.enabled = True
        self._totals: Dict[str, List[float]] = {}
        self._clock = 0.0

    def collect_for(self, connections, interval: float = 2.0
                    ) -> Dict[str, ProcNet]:
        import random

        rows: Dict[str, ProcTuple] = {}
        flows: Dict[str, FlowNet] = {}
        for c in connections:
            if not c.raddr:
                continue
            key = flow_key(c.proto, c.laddr, c.lport, c.raddr, c.rport)
            tot = self._totals.setdefault(key, [0.0, 0.0,
                                                random.uniform(2e3, 9e5)])
            tot[2] = min(4e6, max(500.0, tot[2] * random.uniform(0.6, 1.5)))
            tot[0] += tot[2] * interval
            tot[1] += tot[2] * interval * random.uniform(0.05, 0.3)
            flows[key] = FlowNet(key=key, proto=c.proto, family=c.family,
                                 laddr=c.laddr, lport=c.lport, raddr=c.raddr,
                                 rport=c.rport, pid=c.pid, pname=c.pname,
                                 bytes_in=int(tot[0]), bytes_out=int(tot[1]))
            label = f"{c.pname}.{c.pid}"
            pid, name, b_in, b_out = rows.get(label, (c.pid, c.pname, 0, 0))
            rows[label] = (pid, name, b_in + int(tot[0]), b_out + int(tot[1]))
        self._clock += interval
        return self.ingest(rows, flows, now=self._clock)


# ---------------------------------------------------------------------------
# formatting helpers
# ---------------------------------------------------------------------------

_UNITS: List[Tuple[float, str]] = [
    (1024 ** 4, "T"), (1024 ** 3, "G"), (1024 ** 2, "M"), (1024, "K")]


def human_bytes(n: float, suffix: str = "B") -> str:
    n = float(n)
    for factor, unit in _UNITS:
        if n >= factor:
            return f"{n / factor:.1f}{unit}{suffix}"
    return f"{n:.0f}{suffix}"


def human_rate(n: float) -> str:
    return human_bytes(n) + "/s"
