"""``netmonguru --doctor``: one-screen self-check of the Windows backends.

Every feature that replaces a macOS tool is exercised once and reported as
OK / WARN / FAIL with the reason, so a problem can be diagnosed (or reported)
without reading a traceback.
"""

from __future__ import annotations

import platform
import sys
import time


def run() -> int:
    from . import __version__
    from .core import win

    results = []

    def check(name: str, fn) -> None:
        start = time.monotonic()
        try:
            status, detail = fn()
        except Exception as exc:                        # noqa: BLE001
            status, detail = "FAIL", f"{type(exc).__name__}: {exc}"
        results.append((status, name, detail, time.monotonic() - start))
        print(f"  [{status:<4}] {name:<26} {detail}")

    print(f"NetMonGuru {__version__} doctor — Python "
          f"{platform.python_version()} on {platform.platform()}\n")

    def _platform():
        return ("OK", "Windows") if win.IS_WINDOWS else \
            ("WARN", f"{sys.platform}: this build targets Windows")

    def _admin():
        return ("OK", "elevated") if win.is_admin() else (
            "WARN", "not elevated - no per-process bandwidth, no connection "
                    "cut, fewer process details")

    def _deps():
        import psutil
        import rich
        import textual
        return "OK", (f"textual {textual.__version__}, psutil "
                      f"{psutil.__version__}")

    def _sockets():
        from .core.connections import ConnectionCollector
        c = ConnectionCollector()
        conns = c.collect()
        owned = sum(1 for x in conns if x.pid)
        if not conns:
            return "FAIL", f"no sockets ({'; '.join(c.errors) or 'empty'})"
        return "OK", (f"{len(conns)} sockets via {c.backend}, {owned} with "
                      "an owning process")

    def _estats():
        from .core.connections import ConnectionCollector
        from .core.bandwidth import WindowsNetCollector
        net = WindowsNetCollector()
        if not net.available:
            return "FAIL", net.error or "iphlpapi not available"
        conns = ConnectionCollector().collect()
        net.collect_for(conns)
        time.sleep(1.0)
        procs = net.collect_for(conns)
        if net.error:
            return "WARN", net.error
        return "OK", (f"{len(net.flows)} TCP connections with counters, "
                      f"{len(procs)} processes")

    def _powershell():
        code, text = win.powershell("$PSVersionTable.PSVersion.ToString()", 20)
        return ("OK", f"PowerShell {text.strip()}") if code == 0 else \
            ("FAIL", text.strip()[:120])

    def _authenticode():
        result = win.authenticode([sys.executable])
        if not result:
            return "FAIL", "no answer from Get-AuthenticodeSignature"
        signing, publisher, _issuer, note = next(iter(result.values()))
        return "OK", f"python.exe: {signing} {publisher} {note}".strip()

    def _dns():
        code, text = win.powershell(
            "(Get-DnsClientCache | Measure-Object).Count", 25)
        cache = f"cache: {text.strip()} entries" if code == 0 \
            else f"cache: {text.strip()[:60]}"
        log = "event log: enabled (process names available)" \
            if win.dns_log_enabled() else \
            "event log: disabled (use --dns-capture etw when elevated)"
        return ("OK" if code == 0 else "WARN"), f"{cache}; {log}"

    def _dirs():
        for d in (win.config_dir(), win.cache_dir()):
            d.mkdir(parents=True, exist_ok=True)
            probe = d / ".write-test"
            probe.write_text("ok", "utf-8")
            probe.unlink()
        return "OK", f"{win.config_dir()}  |  {win.cache_dir()}"

    def _keys():
        from .core.ti import load_keys
        keys, warning = load_keys()
        if warning:
            return "WARN", warning
        return "OK", (", ".join(sorted(keys)) or
                      "none configured - local feeds only")

    def _network():
        from .core.ti_feeds import default_fetch
        raw = default_fetch("https://check.torproject.org/torbulkexitlist",
                            {}, None)
        return "OK", f"feed download works ({len(raw) // 1024} KB)"

    def _terminal():
        import os
        if os.environ.get("WT_SESSION"):
            return "OK", "Windows Terminal"
        return "WARN", ("not Windows Terminal - use it (or VS Code's "
                        "terminal) for correct colours, mouse and braille "
                        "map; legacy conhost renders poorly")

    for name, fn in (("platform", _platform), ("administrator", _admin),
                     ("python packages", _deps), ("terminal", _terminal),
                     ("socket table", _sockets),
                     ("TCP statistics", _estats),
                     ("PowerShell", _powershell),
                     ("Authenticode", _authenticode), ("DNS sources", _dns),
                     ("config / cache folders", _dirs), ("API keys", _keys),
                     ("outbound HTTPS", _network)):
        check(name, fn)

    failed = [r for r in results if r[0] == "FAIL"]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed"
          + (" — copy this output into a GitHub issue if something is off."
             if failed else "."))
    return 1 if failed else 0
