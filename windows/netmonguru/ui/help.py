"""Key reference shown by ``?`` - one block per pane plus the global keys."""

GLOBAL_HELP = [
    ("1 … 9", "switch pane: Connections, Map, Bandwidth, Processes, DNS, "
              "Monitor, Intel, Alerts, History"),
    ("/", "filter the current pane        esc  clear filter / close panel"),
    ("space", "pause sampling"),
    ("i", "investigate the selected address or process (TI + whois + OSINT)"),
    ("k", "end connection / process, or block the host"),
    ("?", "this help                       q  quit"),
]

HELP = {
    "tab-conn": ("Connections", [
        ("enter / click", "expand connection details (follows the cursor)"),
        ("m  /  x", "mark row (cursor advances)  /  unmark all"),
        ("f  F  P", "monitor marked rows as endpoint / whole host / whole "
                    "process"),
        ("g", "open the owning process in Processes"),
        ("s  /  r", "cycle sort (Newest first by default)  /  reverse"),
        ("t u e l p", "toggle TCP, UDP, established-only, listening, "
                      "public-only"),
        ("columns", "TI = threat intel verdict, SIG = code signature, "
                    "▼ ▲ = live throughput of the connection"),
    ]),
    "tab-map": ("Map", [
        ("click marker", "select a destination and list its connections"),
        (",  .", "previous / next marker        a  toggle arcs"),
    ]),
    "tab-bw": ("Bandwidth", [
        ("b", "switch view: processes → connections → interfaces"),
        ("enter", "process → its connections; connection → its details"),
        ("↑ ↓  /  n", "the graph follows the selected row"),
    ]),
    "tab-proc": ("Processes", [
        ("enter / click", "process details: binary, signature, autostart "
                          "entries, process tree, its connections"),
        ("tab", "move into the connection list (enter opens, i investigates)"),
        ("i", "process report: Authenticode, Mark-of-the-Web, autostart, open "
              "files, hash → VirusTotal, peers + OSINT"),
        ("P  /  k", "monitor the whole process  /  terminate it"),
    ]),
    "tab-dns": ("DNS", [
        ("TI column", "name matched a domain IOC feed, or looks "
                      "machine-generated (DGA?)"),
        ("/", "filter names, clients and answers"),
    ]),
    "tab-mon": ("Monitor", [
        ("d", "delete the rule under the cursor (upper table)"),
        ("c", "clear closed connections from the history"),
        ("enter", "open a live connection in Connections"),
    ]),
    "tab-intel": ("Intel", [
        ("i", "focus the address box - type an IP, press enter"),
        ("w", "write the selected report as Markdown + JSON"),
        ("R", "re-download the threat feeds now"),
    ]),
    "tab-alerts": ("Alerts", [
        ("enter", "jump to the connection / process the alert is about"),
        ("i", "investigate the address of the alert"),
        ("A", "acknowledge all alerts"),
        ("tab → d", "blocked hosts table: d removes the block"),
        ("rules", "threat, bad-domain, dga-domain, new-listener, unsigned, "
                  "new-process, new-country, upload-spike, beacon"),
    ]),
    "tab-hist": ("History", [
        ("[  ]", "shorter / longer time window (1 h, 24 h, 7 d, all)"),
        ("!", "show only connections that were flagged by threat intel"),
        ("/", "filter by process, address, host, organisation, country, port"),
        ("w", "export what is shown to CSV in ~/netmonguru-reports"),
        ("i", "investigate the address of the selected row"),
    ]),
}
