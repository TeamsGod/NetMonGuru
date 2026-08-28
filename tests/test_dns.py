"""DNS watcher: log/tcpdump parsers and rolling-window cache behaviour."""

from __future__ import annotations

import time
import unittest

from netmonguru.core.dnswatch import (DNSCache, DNSRecord, TcpdumpParser,
                                      parse_log_line)

# Representative `log stream --style compact --info` lines from
# mDNSResponder.  Formats vary across macOS releases, so the parser is
# deliberately tolerant: it keys on "<name> <TYPE> <value>".
LOG_LINES = [
    '2026-08-28 11:02:14.881 Df mDNSResponder [R12] DNSServiceQueryRecord('
    '0x0, 0, "www.google.com.", Addr) RESULT ADD interface 0: '
    'www.google.com. Addr 142.250.203.110 PID[501](firefox)',
    '2026-08-28 11:02:15.104 Df mDNSResponder [R13] DNSServiceQueryRecord('
    '0x0, 0, "github.com.", Addr) RESULT ADD interface 0: github.com. '
    'Addr 140.82.121.4 PID[502](git)',
    '2026-08-28 11:02:16.220 Df mDNSResponder [R14] RESULT ADD interface 0: '
    'cdn.example.org. CNAME edge.example.net. PID[501](firefox)',
    '2026-08-28 11:02:17.001 Df mDNSResponder [R15] RESULT ADD interface 0: '
    'ipv6.example.com. Addr 2606:4700::6810:85e5 PID[501](firefox)',
    '2026-08-28 11:02:18.400 Df mDNSResponder something entirely different',
]

TCPDUMP_LINES = [
    "11:02:14.881234 IP 192.168.1.24.51234 > 1.1.1.1.53: 4919+ A? "
    "www.example.com. (33)",
    "11:02:14.921887 IP 1.1.1.1.53 > 192.168.1.24.51234: 4919 1/0/0 A "
    "93.184.216.34 (49)",
    "11:02:15.100000 IP 192.168.1.24.51235 > 1.1.1.1.53: 5001+ AAAA? "
    "ipv6.example.com. (34)",
    "11:02:15.140000 IP 1.1.1.1.53 > 192.168.1.24.51235: 5001 1/0/0 AAAA "
    "2606:2800:220:1:248:1893:25c8:1946 (62)",
    "11:02:16.000000 IP 1.1.1.1.53 > 192.168.1.24.59999: 7777 1/0/0 A "
    "10.0.0.1 (44)",                       # response with no matching query
]


class TestLogParser(unittest.TestCase):
    def test_a_record_with_client(self):
        recs = parse_log_line(LOG_LINES[0], now=1000.0)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r.name, "www.google.com")
        self.assertEqual(r.rtype, "A")
        self.assertEqual(r.answers, ["142.250.203.110"])
        self.assertEqual(r.client, "firefox")
        self.assertEqual(r.pid, 501)
        self.assertEqual(r.source, "log")

    def test_cname(self):
        recs = parse_log_line(LOG_LINES[2])
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].rtype, "CNAME")
        self.assertEqual(recs[0].name, "cdn.example.org")
        self.assertEqual(recs[0].answers, ["edge.example.net"])

    def test_ipv6_addr_becomes_aaaa(self):
        recs = parse_log_line(LOG_LINES[3])
        self.assertEqual(recs[0].rtype, "AAAA")
        self.assertEqual(recs[0].answers, ["2606:4700::6810:85e5"])

    def test_ignores_unrelated_lines(self):
        self.assertEqual(parse_log_line(LOG_LINES[4]), [])
        self.assertEqual(parse_log_line(""), [])

    def test_duplicate_name_merged(self):
        line = ("RESULT ADD interface 0: a.example.com. Addr 1.2.3.4 "
                "a.example.com. Addr 5.6.7.8")
        recs = parse_log_line(line)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].answers, ["1.2.3.4", "5.6.7.8"])


class TestTcpdumpParser(unittest.TestCase):
    def setUp(self):
        self.parser = TcpdumpParser()

    def test_query_response_correlation(self):
        self.assertEqual(self.parser.feed(TCPDUMP_LINES[0]), [])
        recs = self.parser.feed(TCPDUMP_LINES[1], now=2000.0)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].name, "www.example.com")
        self.assertEqual(recs[0].rtype, "A")
        self.assertEqual(recs[0].answers, ["93.184.216.34"])
        self.assertEqual(recs[0].source, "pcap")

    def test_aaaa(self):
        self.parser.feed(TCPDUMP_LINES[2])
        recs = self.parser.feed(TCPDUMP_LINES[3])
        self.assertEqual(recs[0].rtype, "AAAA")
        self.assertEqual(recs[0].answers,
                         ["2606:2800:220:1:248:1893:25c8:1946"])

    def test_orphan_response_dropped(self):
        self.assertEqual(self.parser.feed(TCPDUMP_LINES[4]), [])


class TestCache(unittest.TestCase):
    def setUp(self):
        self.cache = DNSCache(window=900)
        self.now = time.time()

    def add(self, name, ips, offset=0.0, client="firefox", source="log"):
        self.cache.add(DNSRecord(ts=self.now - offset, name=name,
                                 answers=list(ips), source=source,
                                 client=client, ttl=300))

    def test_index_and_aggregation(self):
        self.add("www.example.com", ["93.184.216.34"])
        self.add("www.example.com", ["93.184.216.34", "93.184.216.35"], 5)
        entries = self.cache.entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].hits, 2)
        self.assertEqual(list(entries[0].addresses),
                         ["93.184.216.34", "93.184.216.35"])
        self.assertEqual(self.cache.name_for("93.184.216.35"),
                         "www.example.com")

    def test_name_normalised(self):
        self.add("WWW.Example.COM.", ["1.2.3.4"])
        self.assertEqual(self.cache.entries()[0].name, "www.example.com")

    def test_window_eviction(self):
        self.add("old.example.com", ["1.1.1.1"], offset=1200)
        self.add("new.example.com", ["2.2.2.2"], offset=10)
        self.cache.evict(self.now)
        names = [e.name for e in self.cache.entries()]
        self.assertEqual(names, ["new.example.com"])
        self.assertEqual(self.cache.name_for("1.1.1.1"), "")
        self.assertEqual(self.cache.name_for("2.2.2.2"), "new.example.com")

    def test_rate_series_shape(self):
        for i in range(10):
            self.add(f"h{i}.example.com", ["1.2.3.4"], offset=i * 30)
        series = self.cache.rate_series(60)
        self.assertEqual(len(series), 60)
        self.assertEqual(sum(series), 10)
        # newest sample sits at the right-hand end
        self.assertGreater(sum(series[-5:]), 0)

    def test_stats(self):
        self.add("a.example.com", ["1.1.1.1", "1.1.1.2"])
        self.add("b.example.com", ["1.1.1.3"])
        s = self.cache.stats()
        self.assertEqual((s["names"], s["addresses"], s["total"]), (2, 3, 2))

    def test_passive_dedup(self):
        from netmonguru.core.dnswatch import DNSWatcher
        w = DNSWatcher(mode="off")
        w.note_reverse("8.8.8.8", "dns.google")
        w.note_reverse("8.8.8.8", "dns.google")
        self.assertEqual(w.cache.stats()["total"], 1)
        self.assertEqual(w.cache.name_for("8.8.8.8"), "dns.google")


    def test_forward_answer_beats_ptr(self):
        """A PTR guess must never overwrite a name we watched resolve."""
        self.add("github.com", ["140.82.121.4"], source="log")
        self.add("lb-140-82-121-4.example", ["140.82.121.4"],
                 source="passive", client="")
        self.assertEqual(self.cache.name_for("140.82.121.4"), "github.com")

    def test_ptr_fills_unnamed_address(self):
        self.add("dns.google", ["8.8.8.8"], source="passive", client="")
        self.assertEqual(self.cache.name_for("8.8.8.8"), "dns.google")
        # ... and a later forward answer takes over
        self.add("real.google.com", ["8.8.8.8"], source="log")
        self.assertEqual(self.cache.name_for("8.8.8.8"), "real.google.com")


if __name__ == "__main__":
    unittest.main()
