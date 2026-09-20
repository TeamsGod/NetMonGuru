# Changelog

## 1.5.0 — 2026-09-20

### Added
- **Processes pane on par with Connections.**
  - `TI` column: worst verdict among the process' peers; processes talking to
    a confirmed-malicious address are pinned first. `SIG` column: code
    signature of the binary.
  - Detail panel on click / `Enter`: executable, user, parent, uptime, memory,
    command line, signature, launch-path flags, traffic, sockets, listening
    ports, flagged peers, and the list of the process' connections with a TI
    label each (flagged first). From that list `Enter` opens the connection,
    `i` investigates the address.
  - `i` — **process investigation** in the Intel pane: signature verification,
    Gatekeeper, SHA-256 → VirusTotal, local context, all public peers with
    their local verdict, and a full TI + WHOIS + OSINT report for the three
    most suspect peers. Exported reports embed the peer reports.
  - `P` / `f` monitor the whole process, `k` terminates or force-kills it,
    `/` filters by name, PID or TI label.

## 1.4.0 — 2026-09-20

### Added
- **Bandwidth per process and per connection.** The Bandwidth pane has three
  views — processes, connections, interfaces — switched with `b`. The graph
  follows the selected row, so any process or single connection can be graphed
  over the 4-minute window. `Enter` on a process filters down to its
  connections, `Enter` on a connection opens its details, `Esc` goes back,
  `/` filters rows by process, PID, address or hostname.
- `--bw-view processes|connections|interfaces` selects the starting view.
- Per-connection throughput from `nettop`'s full listing (one call now yields
  both process and socket counters), with a rolling history per process and
  per socket. `--demo` generates synthetic traffic so the views can be tried
  anywhere.

### Changed
- **The Bandwidth pane now opens per process by default** (was: per
  interface).

### Fixed
- `nettop` output with a leading timestamp column (current macOS layout) had
  the timestamp read as the process label, which produced bogus process names
  in the Processes pane. Both layouts are handled now.

## 1.3.0 — 2026-09-20

### Added
- **Threat intelligence.**
  - `TI` column in Connections, fed by locally matched blocklists: abuse.ch
    Feodo Tracker, SSLBL and ThreatFox, Spamhaus DROP, Emerging Threats
    compromised hosts, FireHOL level 1, Tor exit nodes. Feeds are downloaded
    whole every 6 h and matched in memory — no address leaves the machine.
  - Optional automatic AbuseIPDB check of every new public peer: one lookup
    per address per 24 h, disk cache, daily budget inside the free tier,
    addresses with a feed hit checked first.
  - Confirmed-malicious peers are pinned to the top of the list and raise a
    warning in the summary bar.
- **Intel pane (`7`) and on-demand investigation (`i`).** For the selected
  connection, or an address typed by hand, runs in parallel: AbuseIPDB,
  VirusTotal, ThreatFox, AlienVault OTX, GreyNoise Community; RDAP and
  `whois`; Shodan InternetDB, DNS (PTR + forward confirmation), crt.sh; plus
  the owning process. Ends in one verdict — MALICIOUS / SUSPICIOUS / CLEAN /
  UNKNOWN — with the list of who claimed what. `w` exports the report as
  Markdown + JSON to `~/netmonguru-reports/`, `R` refreshes the feeds.
- **Process trust signals.** `SIG` column (apple / dev-id / store / ad-hoc /
  UNSIGNED / INVALID, `!` for a suspicious launch path such as `/tmp`,
  Downloads or a hidden directory). Investigations add Gatekeeper assessment
  and the binary's SHA-256 looked up in VirusTotal (hash only, never the file).
- **API keys** in `~/.config/netmonguru/keys.toml` (template created on first
  run, mode 600) or environment variables `ABUSEIPDB_KEY`, `VT_API_KEY`,
  `ABUSECH_AUTH_KEY`, `OTX_API_KEY`, `GREYNOISE_KEY`. All optional.
- **New flags:** `--no-ti` (no threat intelligence at all), `--no-ti-auto`
  (feeds and manual investigations only; nothing is sent automatically).

### Fixed
- Files written while running under `sudo` (rules, caches, keys template,
  reports) are handed back to the invoking user, so a later run without
  `sudo` can still write them.

## 1.2.0 — 2026-09-20

### Added
- **Connection detail panel.** A single click or `Enter` on a connection
  expands a panel that follows the cursor: socket state and endpoints, service
  name, first-seen time; remote DNS name, PTR, organisation, ASN, location;
  owning process (path, user, parent, uptime, memory, command line); related
  processes (owner / same peer / same app) and every other socket the process
  holds. `g` jumps to the owner in the Processes pane. `Esc` closes.
- **Monitor pane (`6`).** `m` marks connections, `f` turns the marked ones (or
  the highlighted one) into monitor rules and opens the pane; repeat any time
  to add more. A rule describes the conversation, not the socket, so it
  survives reconnects: `f` = process + protocol + remote address/hostname +
  port, `F` = whole remote host, `P` = whole process. The pane lists rules
  with live/total counts and the matching traffic — live sockets first, newest
  on top, then closed ones with first-seen time and duration. `d` deletes a
  rule, `c` clears closed history, `Enter` opens the connection. Rules persist
  in `~/.config/netmonguru/monitor.json`.
- **End a connection (`k`).** Confirmation dialog with three options: cut just
  this connection through the macOS packet filter (exact socket pair, `block
  return` rules in a private pf anchor, needs `sudo`; the process keeps
  running), terminate the owning process (SIGTERM), or force-kill it
  (SIGKILL). pf rules and the pf enable token are released on exit.
- New default sort **Newest**, `AGE` column and `NEW` badge.

### Changed
- **New connections always appear at the top.** Under every other sort order,
  sockets younger than 20 s are pinned above the rest.
- **Scrolling in Connections is smooth.** The table was cleared and rebuilt
  twice a second, which reset the scroll position and pulled the view back to
  the cursor. Tables are now updated in place: only changed cells are
  rewritten, rows are reordered without clearing, the cursor follows its
  connection and the viewport moves with the content.
- Only the visible pane is rendered, and socket tables only when a new sample
  arrives — lower CPU use with many sockets.
- A row is selected on the first click instead of the second.

### Tests
- 80 unit tests (was 37) and two new headless UI suites:
  `tests/smoke_monitor.py` and `tests/smoke_intel.py`.
