# NetMonGuru for Windows

The Windows build of [NetMonGuru](../README.md) 1.5.0 — the same terminal UI
and the same features, with every macOS-specific backend replaced by its
Windows counterpart. Pure Python: if Python runs on the machine, NetMonGuru
runs.

> **Status: first Windows release.** The port was developed and tested on
> non-Windows machines: all parsers, data structures and the complete UI are
> covered by automated tests, but the calls into Windows itself (TCP
> statistics, `SetTcpEntry`, PowerShell cmdlets) have not yet been run on a
> real Windows host. Run `run.bat --doctor` first — it checks every backend
> and prints what works. Please open an issue with that output if something
> is off.

## Quick start

1. Install **Python 3.9+** from <https://www.python.org/downloads/> and tick
   *Add python.exe to PATH*.
2. Use **Windows Terminal** (built into Windows 11, free in the Store for
   Windows 10). The legacy console cannot draw the map or handle the mouse
   properly.
3. Download this folder and double-click **`run.bat`** — the first start
   creates a virtual environment and installs the three dependencies
   (`textual`, `rich`, `psutil`); later starts are immediate.

```bat
run.bat                 :: normal start
run.bat --doctor        :: self-check of every Windows backend
run.bat --demo          :: synthetic data, to look around safely
```

Manual install, if you prefer:

```powershell
cd windows
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m netmonguru
```

### Run as Administrator for the full picture

| | Standard user | Administrator |
|---|---|---|
| Socket table with owning processes | ✔ | ✔ (also protected system processes) |
| Threat intelligence, Intel pane, OSINT, reports | ✔ | ✔ |
| Monitor pane, connection/process details | ✔ | ✔ |
| Live DNS | cache polling (no process names) | event log with the requesting process |
| **Bandwidth per process / per connection** | ✘ | ✔ |
| **Cut a single connection (`k` → `c`)** | ✘ | ✔ |
| Terminate a process | your own processes | any process |

Right-click *Windows Terminal* → *Run as administrator*, then start
`run.bat` from there.

## What replaces what

| Feature | macOS | Windows |
|---|---|---|
| Sockets + owning process | `lsof` + `netstat` | `psutil` (`GetExtendedTcpTable`) |
| Bandwidth per process / connection | `nettop` | TCP extended statistics (`GetPerTcpConnectionEStats`) per connection, summed per process |
| Live DNS | `log stream` / `tcpdump` | DNS Client event log (`--dns-capture etw`) or `Get-DnsClientCache` polling |
| Code signature (`SIG` column) | `codesign` | Authenticode via `Get-AuthenticodeSignature`, including catalog-signed OS binaries: `microsoft`, `signed`, `UNSIGNED`, `INVALID` |
| Gatekeeper assessment | `spctl` | Mark-of-the-Web (`Zone.Identifier`): was the binary downloaded from the internet, and from where |
| Suspicious launch path (`!`) | `/tmp`, Downloads, hidden dirs | `%TEMP%`, Downloads, Desktop, `Users\Public`, `ProgramData`, Recycle Bin, network shares, and system names such as `svchost.exe` running outside `C:\Windows` |
| Cut one connection | `pf` block rules | `SetTcpEntry(DELETE_TCB)` — the kernel closes the socket **immediately**, nothing is left behind |
| Terminate / force kill | SIGTERM / SIGKILL | `t` terminates the process, `K` terminates it **with its child processes** |
| `whois` | system command | built-in port-43 client (follows registry referrals) |
| Config | `~/.config/netmonguru` | `%APPDATA%\netmonguru` (`keys.toml`, `monitor.json`) |
| Cache / feeds | `~/.cache/netmonguru` | `%LOCALAPPDATA%\netmonguru\cache` |
| Reports | `~/netmonguru-reports` | `%USERPROFILE%\netmonguru-reports` |

Everything else — panes, keys, threat feeds, API sources, Monitor rules, report
format — is identical; see the [main README](../README.md) for the full guide
and [Managing API keys](../README.md#managing-api-keys) (on Windows the file is
`%APPDATA%\netmonguru\keys.toml`; the environment variables are the same).

## Windows-specific notes and limits

* **Bandwidth counts TCP only.** Windows keeps per-connection byte counters
  for TCP; UDP/QUIC traffic (HTTP/3, most video calls) is not attributed to a
  process. The *interfaces* view still shows the true totals. Counters start
  when NetMonGuru first sees a connection, so the RECV/SENT columns mean
  "since NetMonGuru started watching".
* **Cutting works for IPv4 TCP.** Windows offers no API to close an IPv6
  connection from outside the owning process; for those use `t`.
* **DNS with process names** needs the *Microsoft-Windows-DNS-Client/
  Operational* log. If it is already enabled NetMonGuru uses it
  automatically; `--dns-capture etw` from an elevated prompt enables it for
  you (it stays enabled afterwards — disable with
  `wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:false`).
* **PowerShell** (Windows PowerShell 5.1, part of Windows) is used for
  Authenticode and DNS. Scripts are passed on the command line with
  `-ExecutionPolicy Bypass -NoProfile`; nothing is written to disk. In a
  Constrained Language Mode / AppLocker environment these two features may be
  unavailable — `--doctor` tells you.
* **Antivirus / EDR.** A Python process that enumerates sockets, reads other
  processes' paths, launches PowerShell and can terminate processes looks like
  what it is: an admin tool. Expect your EDR to notice it on a managed
  machine; use it where you are allowed to.
* **Terminal.** Windows Terminal or the VS Code terminal. A font with Braille
  glyphs (Cascadia Mono/Code, the default) is needed for the map and graphs.

## Command line

Same options as the macOS build, except:

```
--dns-capture {auto,etw,cache,passive,off}
--doctor            check every Windows backend and exit
```

## Tests

```powershell
.venv\Scripts\python -m unittest discover -s tests     # 102 unit tests
.venv\Scripts\python tests\smoke_monitor.py            # headless UI suites
.venv\Scripts\python tests\smoke_intel.py
.venv\Scripts\python tests\smoke_bandwidth.py
.venv\Scripts\python tests\smoke_processes.py
```

`tests/test_win.py` pins down the Windows-specific pieces: structure sizes and
byte order of the `iphlpapi` rows, Authenticode / DNS cache / DNS event
parsers, launch-path heuristics, Mark-of-the-Web parsing, the per-process
aggregation of connection counters, and the whois client.
