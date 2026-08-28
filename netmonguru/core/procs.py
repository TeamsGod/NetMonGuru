"""Per-process view: socket ownership merged with nettop throughput.

The socket table alone already tells us which process talks to whom, so the
process pane stays useful even when ``nettop`` is unavailable (non-macOS, or
a restricted environment) - the throughput columns are simply empty then.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .models import Connection, ProcNet


@dataclass(slots=True)
class ProcRow:
    pid: Optional[int]
    name: str
    in_rate: float = 0.0
    out_rate: float = 0.0
    bytes_in: int = 0
    bytes_out: int = 0
    conns: int = 0
    established: int = 0
    listen_ports: List[int] = field(default_factory=list)
    remotes: int = 0

    @property
    def traffic(self) -> float:
        return self.in_rate + self.out_rate


def aggregate(connections: Iterable[Connection],
              procs: Dict[str, ProcNet]) -> List[ProcRow]:
    """Group sockets by owning process and attach nettop rates."""
    rows: Dict[object, ProcRow] = {}
    peers: Dict[object, set] = {}

    for c in connections:
        key = c.pid if c.pid is not None else f"name:{c.pname}"
        row = rows.get(key)
        if row is None:
            row = rows[key] = ProcRow(pid=c.pid, name=c.pname or "?")
            peers[key] = set()
        row.conns += 1
        if c.state == "ESTABLISHED":
            row.established += 1
        if c.is_listening and c.lport:
            if c.lport not in row.listen_ports:
                row.listen_ports.append(c.lport)
        if c.raddr:
            peers[key].add(c.raddr)

    for key, addrs in peers.items():
        rows[key].remotes = len(addrs)

    by_pid = {r.pid: r for r in rows.values() if r.pid is not None}
    by_name: Dict[str, ProcRow] = {}
    for r in rows.values():
        by_name.setdefault(r.name.lower(), r)

    for p in procs.values():
        row = None
        if p.pid is not None:
            row = by_pid.get(p.pid)
        if row is None:
            row = by_name.get(p.name.lower())
        if row is None:
            key = f"nettop:{p.pid}:{p.name}"
            row = rows[key] = ProcRow(pid=p.pid, name=p.name)
        row.in_rate += p.in_rate
        row.out_rate += p.out_rate
        row.bytes_in += p.bytes_in
        row.bytes_out += p.bytes_out

    out = list(rows.values())
    out.sort(key=lambda r: (-r.traffic, -r.established, -r.conns,
                            r.name.lower()))
    return out
