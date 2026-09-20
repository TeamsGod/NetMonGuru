"""macOS security context for a process: how it persists, what it is entitled
to, where it sits in the process tree and which files it has open.

All of it is local and read-only.  Persistence and the tree are cheap and
shown in the process detail panel; entitlements and open files cost a
subprocess each and are collected only for an investigation report.
"""

from __future__ import annotations

import os
import plistlib
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

LAUNCHD_DIRS = [
    ("/Library/LaunchDaemons", "system daemon"),
    ("/Library/LaunchAgents", "agent for all users"),
    ("~/Library/LaunchAgents", "agent for this user"),
    ("/System/Library/LaunchDaemons", "Apple daemon"),
    ("/System/Library/LaunchAgents", "Apple agent"),
]

#: entitlements worth a second look on something that talks to the network
NOTABLE_ENTITLEMENTS = {
    "com.apple.security.get-task-allow":
        "debuggable (get-task-allow) — never on a release build",
    "com.apple.security.cs.disable-library-validation":
        "loads unsigned libraries (library validation off)",
    "com.apple.security.cs.allow-unsigned-executable-memory":
        "unsigned executable memory allowed",
    "com.apple.security.cs.allow-dyld-environment-variables":
        "honours DYLD_* variables (injection surface)",
    "com.apple.security.cs.disable-executable-page-protection":
        "executable page protection off",
    "com.apple.private.tcc.allow": "private TCC bypass entitlement",
    "com.apple.rootless.install": "may modify SIP-protected locations",
    "com.apple.security.network.server": "sandbox: may accept connections",
    "com.apple.security.network.client": "sandbox: may connect out",
    "com.apple.security.device.camera": "camera",
    "com.apple.security.device.audio-input": "microphone",
    "com.apple.security.files.all": "all files",
}


@dataclass
class LaunchItem:
    label: str
    plist: str
    scope: str
    program: str
    run_at_load: bool = False
    keep_alive: bool = False

    def describe(self) -> str:
        flags = [f for f, on in (("RunAtLoad", self.run_at_load),
                                 ("KeepAlive", self.keep_alive)) if on]
        return (f"{self.label} — {self.scope}"
                + (f" [{', '.join(flags)}]" if flags else "")
                + f" — {self.plist}")


@dataclass
class ProcContext:
    pid: Optional[int] = None
    exe: str = ""
    persistence: List[LaunchItem] = field(default_factory=list)
    tree: List[Tuple[int, str]] = field(default_factory=list)      # root→self
    children: List[Tuple[int, str]] = field(default_factory=list)
    entitlements: List[str] = field(default_factory=list)
    sandboxed: Optional[bool] = None
    hardened: Optional[bool] = None
    open_files: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def tree_text(self) -> str:
        return " → ".join(f"{name} ({pid})" for pid, name in self.tree)


# ---------------------------------------------------------------------------
# launchd
# ---------------------------------------------------------------------------

def parse_launchd_plist(data: bytes, path: str, scope: str
                        ) -> Optional[LaunchItem]:
    try:
        d = plistlib.loads(data)
    except Exception:                                   # noqa: BLE001
        return None
    if not isinstance(d, dict):
        return None
    args = d.get("ProgramArguments") or []
    program = d.get("Program") or (args[0] if args else "")
    if not program:
        return None
    keep = d.get("KeepAlive")
    return LaunchItem(label=str(d.get("Label") or Path(path).stem),
                      plist=path, scope=scope, program=str(program),
                      run_at_load=bool(d.get("RunAtLoad")),
                      keep_alive=bool(keep) if not isinstance(keep, dict)
                      else True)


class LaunchdIndex:
    """program path -> launchd jobs that start it.  Rescanned every 5 min."""

    def __init__(self, dirs=None, ttl: float = 300.0) -> None:
        self.dirs = dirs if dirs is not None else LAUNCHD_DIRS
        self.ttl = ttl
        self._items: List[LaunchItem] = []
        self._stamp = 0.0

    def items(self) -> List[LaunchItem]:
        now = time.monotonic()
        if self._stamp and now - self._stamp < self.ttl:
            return self._items
        found: List[LaunchItem] = []
        for folder, scope in self.dirs:
            root = Path(os.path.expanduser(folder))
            # under sudo "~" is still the invoking user's home on macOS
            try:
                plists = sorted(root.glob("*.plist"))
            except OSError:
                continue
            for p in plists:
                try:
                    item = parse_launchd_plist(p.read_bytes(), str(p), scope)
                except OSError:
                    continue
                if item is not None:
                    found.append(item)
        self._items, self._stamp = found, now
        return found

    def for_exe(self, exe: str) -> List[LaunchItem]:
        if not exe:
            return []
        real = os.path.realpath(exe)
        bundle = re.match(r"^(.*?\.app)/", exe + "/")
        out = []
        for item in self.items():
            prog = item.program
            if prog in (exe, real) or os.path.realpath(prog) == real:
                out.append(item)
            elif bundle and prog.startswith(bundle.group(1) + "/"):
                out.append(item)           # helper inside the same .app
        return out


# ---------------------------------------------------------------------------
# code signing details
# ---------------------------------------------------------------------------

def parse_entitlements(xml: bytes) -> Tuple[List[str], Optional[bool]]:
    """``codesign -d --entitlements :-`` output -> (notable lines, sandboxed).
    Older codesign prefixes the plist with a binary header: cut to ``<?xml``."""
    start = xml.find(b"<?xml")
    if start < 0:
        start = xml.find(b"<plist")
    if start < 0:
        return [], None
    try:
        d = plistlib.loads(xml[start:])
    except Exception:                                   # noqa: BLE001
        return [], None
    if not isinstance(d, dict):
        return [], None
    notable = []
    for key, text in NOTABLE_ENTITLEMENTS.items():
        value = d.get(key)
        if value in (None, False, [], ""):
            continue
        notable.append(text)
    return notable, bool(d.get("com.apple.security.app-sandbox"))


def parse_hardened(codesign_dv: str) -> Optional[bool]:
    """``flags=0x10000(runtime)`` in ``codesign -dv`` = hardened runtime."""
    m = re.search(r"flags=0x[0-9a-fA-F]+\(([^)]*)\)", codesign_dv or "")
    if not m:
        return None if "flags=" not in (codesign_dv or "") else False
    return "runtime" in m.group(1)


def parse_lsof_files(output: str, limit: int = 40) -> List[str]:
    """``lsof -p PID -Fftn`` -> regular files, most interesting first."""
    files, ftype = [], ""
    for line in output.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "t":
            ftype = value
        elif tag == "n" and ftype == "REG":
            files.append(value)
    boring = ("/System/", "/usr/lib/", "/usr/share/", "/Library/Apple/",
              "/private/var/db/", ".dylib", "/Frameworks/", ".car", ".ttf",
              ".ttc", "/icu", ".nib", ".strings")
    seen, keep, rest = set(), [], []
    for f in files:
        if f in seen:
            continue
        seen.add(f)
        (rest if any(b in f for b in boring) else keep).append(f)
    return (keep + rest)[:limit]


class MacContext:
    def __init__(self, run=subprocess.run, launchd: LaunchdIndex = None
                 ) -> None:
        self._run = run
        self.launchd = launchd or LaunchdIndex()
        self.codesign = shutil.which("codesign") or ""
        self.lsof = shutil.which("lsof") or ""

    def collect(self, pid: Optional[int], exe: str = "", deep: bool = False
                ) -> ProcContext:
        ctx = ProcContext(pid=pid, exe=exe)
        try:
            import psutil

            if pid:
                proc = psutil.Process(pid)
                if not exe:
                    try:
                        ctx.exe = exe = proc.exe()
                    except Exception:                   # noqa: BLE001
                        pass
                chain = []
                for parent in reversed(proc.parents()):
                    try:
                        chain.append((parent.pid, parent.name()))
                    except Exception:                   # noqa: BLE001
                        chain.append((parent.pid, "?"))
                chain.append((pid, proc.name()))
                ctx.tree = chain
                try:
                    ctx.children = [(c.pid, c.name())
                                    for c in proc.children()[:12]]
                except Exception:                       # noqa: BLE001
                    pass
        except Exception as exc:                        # noqa: BLE001
            ctx.notes.append(f"process tree: {type(exc).__name__}")

        ctx.persistence = self.launchd.for_exe(exe)
        if len(ctx.tree) >= 2 and ctx.tree[-2][1] in ("launchd",) \
                and not ctx.persistence and exe and "/System/" not in exe \
                and ".app/" not in exe:
            ctx.notes.append("started by launchd but no launchd job names "
                             "this binary (login item, XPC service, or a "
                             "job plist that was removed)")

        if deep and exe and self.codesign:
            try:
                p = self._run([self.codesign, "-d", "--entitlements", ":-",
                               exe], capture_output=True, timeout=10)
                ctx.entitlements, ctx.sandboxed = parse_entitlements(
                    p.stdout or b"")
                dv = self._run([self.codesign, "-dv", exe],
                               capture_output=True, text=True, timeout=10)
                ctx.hardened = parse_hardened((dv.stdout or "")
                                              + (dv.stderr or ""))
            except Exception as exc:                    # noqa: BLE001
                ctx.notes.append(f"entitlements: {exc}"[:100])
        if deep and pid and self.lsof:
            try:
                p = self._run([self.lsof, "-nP", "-p", str(pid), "-Fftn"],
                              capture_output=True, text=True, timeout=10)
                ctx.open_files = parse_lsof_files(p.stdout or "")
            except Exception as exc:                    # noqa: BLE001
                ctx.notes.append(f"open files: {exc}"[:100])
        return ctx
