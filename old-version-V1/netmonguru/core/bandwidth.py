"""Per-interface bandwidth sampling (psutil) and per-process throughput
(macOS ``nettop``)."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from .models import NicSample, ProcNet

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
# nettop - per process throughput on macOS
# ---------------------------------------------------------------------------

_NETTOP_ROW = re.compile(r"^(?P<name>.+?)\.(?P<pid>\d+)$")


def parse_nettop(output: str) -> Dict[str, Tuple[Optional[int], str, int, int]]:
    """Parse ``nettop -P -L 1 -x -J bytes_in,bytes_out -n`` CSV output.

    Returns ``{key: (pid, name, bytes_in, bytes_out)}``.
    """
    rows: Dict[str, Tuple[Optional[int], str, int, int]] = {}
    idx_in = idx_out = None
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
        if not label or label.lower().startswith("time"):
            continue
        try:
            b_in = int(parts[idx_in] or 0)
            b_out = int(parts[idx_out] or 0)
        except ValueError:
            continue
        m = _NETTOP_ROW.match(label)
        if m:
            name, pid = m.group("name"), int(m.group("pid"))
        else:
            name, pid = label, None
        rows[label] = (pid, name, b_in, b_out)
    return rows


class ProcessNetCollector:
    """Samples ``nettop`` and derives per-process rates between our own runs."""

    def __init__(self, enabled: bool = True) -> None:
        self.available = shutil.which("nettop") is not None
        self.enabled = enabled and self.available
        self.error = ""
        self._prev: Dict[str, Tuple[int, int]] = {}
        self._prev_ts: Optional[float] = None

    def collect(self) -> Dict[str, ProcNet]:
        if not self.enabled:
            return {}
        try:
            res = subprocess.run(
                ["nettop", "-P", "-L", "1", "-x", "-n",
                 "-J", "bytes_in,bytes_out"],
                capture_output=True, text=True, timeout=10, check=False)
        except Exception as exc:                       # noqa: BLE001
            self.error = str(exc)[:160]
            self.enabled = False
            return {}
        if not res.stdout.strip():
            self.error = (res.stderr or "nettop returned no data").strip()[:160]
            self.enabled = False
            return {}

        rows = parse_nettop(res.stdout)
        now = time.monotonic()
        dt = (now - self._prev_ts) if self._prev_ts else 0.0
        out: Dict[str, ProcNet] = {}
        for key, (pid, name, b_in, b_out) in rows.items():
            r_in = r_out = 0.0
            if dt > 0 and key in self._prev:
                p_in, p_out = self._prev[key]
                r_in = max(0, b_in - p_in) / dt
                r_out = max(0, b_out - p_out) / dt
            self._prev[key] = (b_in, b_out)
            out[key] = ProcNet(pid=pid, name=name, bytes_in=b_in,
                               bytes_out=b_out, in_rate=r_in, out_rate=r_out)
        self._prev_ts = now
        return out


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
