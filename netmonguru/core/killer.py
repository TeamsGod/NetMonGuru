"""Ending a connection.

macOS has no supported way to close one socket that belongs to another
process (no ``ss -K`` / ``tcpdrop``), so there are two honest options:

``terminate_process``
    signal the owning process.  The kernel closes every socket it holds, so
    the connection is gone at once - together with the rest of the process.

``PfCutter``
    cut just this connection at the packet filter.  A pair of ``block return``
    rules for the exact 4-tuple is loaded into a private pf anchor and the
    matching states are killed.  From that moment no packet of the connection
    gets through; pf answers the next packet from either side with a TCP RST,
    so the application sees "connection reset" as soon as it touches the
    socket (an idle socket lingers in the table until then).  The process
    keeps running and may reconnect - a new connection has a new local port
    and is not affected.  Needs root.

The anchor lives under ``com.apple/`` because the stock ``/etc/pf.conf`` only
evaluates ``anchor "com.apple/*"`` - this way nothing in ``/etc`` is touched.
pf is enabled with a reference token (``pfctl -E``) and released on exit, so
the machine is left the way it was found.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import signal
import subprocess
from typing import Callable, List, Optional, Tuple

from .models import Connection

ANCHOR = "com.apple/250.NetMonGuru"

Runner = Callable[[List[str], str], Tuple[int, str]]


def _run(cmd: List[str], stdin: str = "") -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                           timeout=8)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as exc:                            # noqa: BLE001
        return 1, str(exc)


# ---------------------------------------------------------------------------
# process
# ---------------------------------------------------------------------------

def terminate_process(pid: Optional[int], force: bool = False
                      ) -> Tuple[bool, str]:
    """SIGTERM (or SIGKILL) the process that owns the connection."""
    if not pid:
        return False, "owning process unknown - run with sudo to attribute it"
    if pid <= 1 or pid == os.getpid() or pid == os.getppid():
        return False, f"refusing to signal pid {pid}"
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return True, f"pid {pid} already gone"
    except PermissionError:
        return False, f"not allowed to signal pid {pid} - run with sudo"
    except Exception as exc:                            # noqa: BLE001
        return False, f"kill {pid}: {exc}"
    return True, f"{'SIGKILL' if force else 'SIGTERM'} sent to pid {pid}"


# ---------------------------------------------------------------------------
# packet filter
# ---------------------------------------------------------------------------

def _addr(addr: str) -> str:
    addr = (addr or "").strip("[]").split("%")[0]
    if not addr or addr in ("*", "0.0.0.0", "::"):
        return "any"
    ipaddress.ip_address(addr)                # raises on anything odd
    return addr


def pf_rules(c: Connection) -> List[str]:
    """The two rules (one per direction) that cut exactly this 4-tuple."""
    if not c.raddr or not c.rport or not c.lport:
        raise ValueError("not a connected socket")
    proto = c.proto.lower()
    if proto not in ("tcp", "udp"):
        raise ValueError(f"unsupported protocol {c.proto}")
    local, remote = _addr(c.laddr), _addr(c.raddr)
    if remote == "any":
        raise ValueError("no remote address")
    af = "inet6" if ":" in remote else "inet"
    lport, rport = int(c.lport), int(c.rport)
    return [
        f"block return quick {af} proto {proto} from {local} port {lport} "
        f"to {remote} port {rport}",
        f"block return quick {af} proto {proto} from {remote} port {rport} "
        f"to {local} port {lport}",
    ]


class PfCutter:
    def __init__(self, runner: Runner = _run, anchor: str = ANCHOR,
                 is_root: Optional[bool] = None,
                 pfctl: Optional[str] = None) -> None:
        self.run = runner
        self.anchor = anchor
        self.pfctl = pfctl if pfctl is not None else (
            shutil.which("pfctl") or "")
        self.is_root = (os.geteuid() == 0) if is_root is None else is_root
        self.rules: List[str] = []
        self.token = ""
        self.cut_keys: set = set()

    @property
    def available(self) -> bool:
        return bool(self.pfctl) and self.is_root

    @property
    def why_not(self) -> str:
        if not self.pfctl:
            return "pfctl not found (macOS only)"
        if not self.is_root:
            return "needs root - start NetMonGuru with sudo"
        return ""

    def cut(self, c: Connection) -> Tuple[bool, str]:
        if not self.available:
            return False, self.why_not
        try:
            new = [r for r in pf_rules(c) if r not in self.rules]
        except ValueError as exc:
            return False, str(exc)

        if not self.token:
            code, out = self.run([self.pfctl, "-E"], "")
            m = re.search(r"Token\s*:\s*(\d+)", out)
            if m:
                self.token = m.group(1)
            elif code != 0 and "already enabled" not in out.lower():
                return False, f"pfctl -E: {out[-80:]}"

        rules = self.rules + new
        code, out = self.run([self.pfctl, "-a", self.anchor, "-f", "-"],
                             "\n".join(rules) + "\n")
        if code != 0:
            return False, f"pfctl load: {out[-80:]}"
        self.rules = rules
        self.cut_keys.add(c.key)

        # states created before the rules existed would keep passing packets
        local, remote = _addr(c.laddr), _addr(c.raddr)
        if local != "any":
            self.run([self.pfctl, "-k", local, "-k", remote], "")
            self.run([self.pfctl, "-k", remote, "-k", local], "")
        else:
            self.run([self.pfctl, "-k", remote], "")
        return True, f"cut {c.local} ⇄ {c.remote} (pf, {len(self.rules)} rules)"

    def release(self) -> None:
        """Remove our rules and give back the pf enable reference."""
        if not self.pfctl or not self.is_root:
            return
        if self.rules:
            self.run([self.pfctl, "-a", self.anchor, "-F", "rules"], "")
            self.rules = []
        if self.token:
            self.run([self.pfctl, "-X", self.token], "")
            self.token = ""
