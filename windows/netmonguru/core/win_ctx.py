"""Windows security context for a process: how it persists, where it sits in
the process tree and which files it has open - the counterpart of
``macos_ctx`` (same ``ProcContext``, so the UI and the reports do not care).

Persistence sources
    * ``Run`` / ``RunOnce`` keys (HKLM + HKCU, 64- and 32-bit views)
    * Startup folders (per user and all users)
    * services (``psutil.win_service_iter``)
    * scheduled tasks (``schtasks /query /fo csv /v``)
"""

from __future__ import annotations

import csv
import io
import os
import re
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple

from .macos_ctx import LaunchItem, ProcContext
from .win import IS_WINDOWS, NO_WINDOW

RUN_KEYS = [
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run",
     "Run key (all users)"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "RunOnce key (all users)"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
     "Run key (all users, 32-bit)"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run",
     "Run key (this user)"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "RunOnce key (this user)"),
]

_EXE = re.compile(r'^\s*"([^"]+)"|^\s*(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|dll))'
                  r'(?=\s|$|,)', re.I)


def command_exe(command: str) -> str:
    """``"C:\\Program Files\\App\\app.exe" --min`` -> the executable path.
    Handles quoted paths, unquoted paths with spaces, and environment
    variables."""
    if not command:
        return ""
    command = os.path.expandvars(command.strip())
    m = _EXE.match(command)
    if not m:
        return command.split()[0] if command.split() else ""
    return (m.group(1) or m.group(2) or "").strip()


def parse_schtasks(text: str) -> List[Tuple[str, str]]:
    """``schtasks /query /fo csv /v`` -> ``[(task name, command)]``.  Column
    names are localised, so they are located by position in the header of the
    English layout and, failing that, by looking for a path-like cell."""
    out: List[Tuple[str, str]] = []
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return out
    header = [h.strip().lower() for h in rows[0]]
    name_i = header.index("taskname") if "taskname" in header else 1
    cmd_i = header.index("task to run") if "task to run" in header else -1
    seen = set()
    for row in rows[1:]:
        if len(row) <= max(name_i, cmd_i) or row == rows[0]:
            continue
        name = row[name_i].strip()
        if cmd_i >= 0:
            command = row[cmd_i].strip()
        else:
            command = next((c for c in row if re.search(
                r"\.(exe|bat|cmd|ps1|vbs)\b", c, re.I)), "")
        if not name or not command or command.upper().startswith("COM HANDLER") \
                or (name, command) in seen or name.lower() == "taskname":
            continue
        seen.add((name, command))
        out.append((name, command))
    return out


class AutostartIndex:
    def __init__(self, ttl: float = 300.0, run=subprocess.run) -> None:
        self.ttl = ttl
        self._run = run
        self._items: List[LaunchItem] = []
        self._stamp = 0.0

    # each source is best-effort: a locked-down machine may deny any of them
    def _run_keys(self) -> List[LaunchItem]:
        items: List[LaunchItem] = []
        try:
            import winreg
        except ImportError:
            return items
        hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE,
                 "HKCU": winreg.HKEY_CURRENT_USER}
        for hive, path, scope in RUN_KEYS:
            try:
                with winreg.OpenKey(hives[hive], path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                        except OSError:
                            break
                        i += 1
                        items.append(LaunchItem(
                            label=str(name), plist=f"{hive}\\{path}",
                            scope=scope, program=command_exe(str(value)),
                            run_at_load=True))
            except OSError:
                continue
        return items

    def _startup_folders(self) -> List[LaunchItem]:
        items: List[LaunchItem] = []
        for base, scope in (
                (os.environ.get("APPDATA", ""), "Startup folder (this user)"),
                (os.environ.get("PROGRAMDATA", ""),
                 "Startup folder (all users)")):
            if not base:
                continue
            folder = Path(base) / "Microsoft" / "Windows" / "Start Menu" / \
                "Programs" / "Startup"
            try:
                for f in folder.iterdir():
                    if f.name.lower() != "desktop.ini":
                        # a .lnk target needs COM to resolve: match by name
                        items.append(LaunchItem(
                            label=f.name, plist=str(folder), scope=scope,
                            program=str(f) if f.suffix.lower() != ".lnk"
                            else f"lnk:{f.stem.lower()}", run_at_load=True))
            except OSError:
                continue
        return items

    def _services(self) -> List[LaunchItem]:
        items: List[LaunchItem] = []
        try:
            import psutil
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                except Exception:                       # noqa: BLE001
                    continue
                items.append(LaunchItem(
                    label=str(info.get("name")),
                    plist=f"service ({info.get('start_type')})",
                    scope="Windows service",
                    program=command_exe(str(info.get("binpath") or "")),
                    run_at_load=info.get("start_type") == "automatic",
                    keep_alive=False))
        except Exception:                               # noqa: BLE001
            pass
        return items

    def _tasks(self) -> List[LaunchItem]:
        try:
            p = self._run(["schtasks", "/query", "/fo", "csv", "/v"],
                          capture_output=True, text=True, timeout=40,
                          creationflags=NO_WINDOW, errors="replace")
        except Exception:                               # noqa: BLE001
            return []
        return [LaunchItem(label=name, plist="Task Scheduler",
                           scope="scheduled task", program=command_exe(cmd))
                for name, cmd in parse_schtasks(p.stdout or "")]

    def items(self) -> List[LaunchItem]:
        now = time.monotonic()
        if self._stamp and now - self._stamp < self.ttl:
            return self._items
        found: List[LaunchItem] = []
        if IS_WINDOWS:
            for source in (self._run_keys, self._startup_folders,
                           self._services, self._tasks):
                found += source()
        self._items, self._stamp = found, now
        return found

    def for_exe(self, exe: str) -> List[LaunchItem]:
        if not exe:
            return []
        low = os.path.normcase(os.path.normpath(exe)).lower()
        stem = Path(exe.replace("\\", "/")).stem.lower()
        out = []
        for item in self.items():
            prog = item.program
            if prog.startswith("lnk:"):
                if prog[4:] == stem:
                    out.append(item)
            elif prog and os.path.normcase(os.path.normpath(prog)).lower() \
                    == low:
                out.append(item)
        # svchost hosts dozens of services: listing them all says nothing
        if stem == "svchost" and len(out) > 3:
            return out[:1] + [LaunchItem(
                label=f"… and {len(out) - 1} more services share svchost.exe",
                plist="", scope="Windows service", program=exe)]
        return out


class WinContext:
    """Same interface as ``MacContext``."""

    def __init__(self, index: Optional[AutostartIndex] = None) -> None:
        self.launchd = index or AutostartIndex()

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
                if deep:
                    try:
                        boring = ("\\windows\\", ".mui", ".nls", ".ttf",
                                  ".dll", "\\fonts\\")
                        files = [f.path for f in proc.open_files()]
                        keep = [f for f in files
                                if not any(b in f.lower() for b in boring)]
                        rest = [f for f in files if f not in keep]
                        ctx.open_files = (keep + rest)[:40]
                    except Exception as exc:            # noqa: BLE001
                        ctx.notes.append("open files: "
                                         f"{type(exc).__name__}")
        except Exception as exc:                        # noqa: BLE001
            ctx.notes.append(f"process tree: {type(exc).__name__}")
        ctx.persistence = self.launchd.for_exe(exe)
        # a parent that has already exited is a classic of injected / dropped
        # payloads, and of nothing else that is common on a desktop
        if pid and len(ctx.tree) == 1 and exe and \
                "\\windows\\" not in exe.lower():
            ctx.notes.append("parent process no longer exists (orphaned)")
        return ctx


def make_context():
    from .macos_ctx import MacContext
    return WinContext() if IS_WINDOWS else MacContext()
