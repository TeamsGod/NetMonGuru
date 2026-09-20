"""Parser tests against captured macOS command output."""

from __future__ import annotations

import unittest

from netmonguru.core.bandwidth import human_bytes, human_rate, parse_nettop
from netmonguru.core.connections import (merge, parse_lsof, parse_netstat,
                                         _split_dotted, _split_hostport)
from netmonguru.core.models import classify_address, is_routable
from netmonguru.data.landmask import is_land
from netmonguru.ui.widgets.braille import braille_bars, sparkline

LSOF_SAMPLE = """p501
cfirefox
f45
tIPv4
PTCP
n192.168.1.24:51344->142.250.203.110:443
TST=ESTABLISHED
TQR=0
TQS=0
f46
tIPv6
PTCP
n[2a00:1450:401b:800::200e]:51360->[2606:4700::6810:85e5]:443
TST=ESTABLISHED
f47
tIPv4
PUDP
n*:5353
p1
claunchd
f12
tIPv4
PTCP
n*:22
TST=LISTEN
f13
tIPv4
PTCP
n127.0.0.1:631
TST=LISTEN
"""

NETSTAT_SAMPLE = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.24.51344     142.250.203.110.443    ESTABLISHED
tcp4       0      0  *.22                   *.*                    LISTEN
tcp46      0      0  *.8080                 *.*                    LISTEN
tcp6       0      0  fe80::1%lo0.5000       *.*                    LISTEN
udp4       0      0  *.5353                 *.*
udp4       0      0  192.168.1.24.68        *.*
Active LOCAL (UNIX) domain sockets
"""

NETTOP_SAMPLE = """time,,bytes_in,bytes_out,
12:01:02.123456,,,,
firefox.501,,1048576,262144,
Microsoft Teams.503,,52428800,1048576,
kernel_task.0,,0,0,
"""


class TestLsof(unittest.TestCase):
    def setUp(self):
        self.conns = parse_lsof(LSOF_SAMPLE)

    def test_count(self):
        self.assertEqual(len(self.conns), 5)

    def test_established_tcp(self):
        c = self.conns[0]
        self.assertEqual(c.proto, "TCP")
        self.assertEqual(c.family, "IPv4")
        self.assertEqual(c.laddr, "192.168.1.24")
        self.assertEqual(c.lport, 51344)
        self.assertEqual(c.raddr, "142.250.203.110")
        self.assertEqual(c.rport, 443)
        self.assertEqual(c.state, "ESTABLISHED")
        self.assertEqual(c.pid, 501)
        self.assertEqual(c.pname, "firefox")
        self.assertTrue(c.is_established)

    def test_ipv6(self):
        c = self.conns[1]
        self.assertEqual(c.family, "IPv6")
        self.assertEqual(c.laddr, "2a00:1450:401b:800::200e")
        self.assertEqual(c.raddr, "2606:4700::6810:85e5")
        self.assertEqual(c.rport, 443)
        self.assertEqual(c.remote, "[2606:4700::6810:85e5]:443")

    def test_udp_wildcard(self):
        c = self.conns[2]
        self.assertEqual(c.proto, "UDP")
        self.assertEqual(c.laddr, "")
        self.assertEqual(c.lport, 5353)
        self.assertTrue(c.is_listening)

    def test_process_boundary(self):
        self.assertEqual([c.pname for c in self.conns[3:]],
                         ["launchd", "launchd"])
        self.assertEqual(self.conns[3].state, "LISTEN")
        self.assertEqual(self.conns[4].laddr, "127.0.0.1")
        self.assertEqual(self.conns[4].lport, 631)


class TestNetstat(unittest.TestCase):
    def setUp(self):
        self.conns = parse_netstat(NETSTAT_SAMPLE)

    def test_count(self):
        self.assertEqual(len(self.conns), 6)

    def test_fields(self):
        c = self.conns[0]
        self.assertEqual((c.proto, c.laddr, c.lport, c.raddr, c.rport,
                          c.state),
                         ("TCP", "192.168.1.24", 51344, "142.250.203.110",
                          443, "ESTABLISHED"))

    def test_scope_id_stripped(self):
        c = [x for x in self.conns if x.lport == 5000][0]
        self.assertEqual(c.laddr, "fe80::1")

    def test_udp_has_no_state(self):
        udp = [c for c in self.conns if c.proto == "UDP"]
        self.assertEqual(len(udp), 2)
        self.assertEqual(udp[0].state, "")


class TestMerge(unittest.TestCase):
    def test_dedup_and_supplement(self):
        merged = merge(parse_lsof(LSOF_SAMPLE), parse_netstat(NETSTAT_SAMPLE))
        # the shared ESTABLISHED row must not be duplicated and must keep
        # its process attribution
        est = [c for c in merged if c.raddr == "142.250.203.110"]
        self.assertEqual(len(est), 1)
        self.assertEqual(est[0].pname, "firefox")
        # netstat-only sockets survive
        self.assertTrue(any(c.lport == 8080 for c in merged))
        # totals: 5 from lsof + 3 netstat-only rows
        self.assertEqual(len(merged), 8)


class TestNettop(unittest.TestCase):
    def test_parse(self):
        rows = parse_nettop(NETTOP_SAMPLE)
        self.assertIn("firefox.501", rows)
        pid, name, b_in, b_out = rows["firefox.501"]
        self.assertEqual((pid, name, b_in, b_out), (501, "firefox", 1048576,
                                                    262144))
        self.assertEqual(rows["Microsoft Teams.503"][1], "Microsoft Teams")
        self.assertNotIn("time", rows)


class TestAddressHelpers(unittest.TestCase):
    def test_split_hostport(self):
        self.assertEqual(_split_hostport("1.2.3.4:443"), ("1.2.3.4", 443))
        self.assertEqual(_split_hostport("[::1]:80"), ("::1", 80))
        self.assertEqual(_split_hostport("*:5353"), ("", 5353))
        self.assertEqual(_split_hostport("*:*"), ("", 0))

    def test_split_dotted(self):
        self.assertEqual(_split_dotted("192.168.1.1.53"), ("192.168.1.1", 53))
        self.assertEqual(_split_dotted("fe80::1%en0.5353"), ("fe80::1", 5353))
        self.assertEqual(_split_dotted("*.*"), ("", 0))

    def test_classify(self):
        self.assertEqual(classify_address("8.8.8.8"), "public")
        self.assertEqual(classify_address("192.168.1.5"), "private")
        self.assertEqual(classify_address("127.0.0.1"), "loopback")
        self.assertEqual(classify_address("224.0.0.251"), "multicast")
        self.assertEqual(classify_address(""), "wildcard")
        self.assertTrue(is_routable("1.1.1.1"))
        self.assertFalse(is_routable("10.0.0.1"))


class TestLandmask(unittest.TestCase):
    def test_known_points(self):
        self.assertTrue(is_land(52.23, 21.01))     # Warsaw
        self.assertTrue(is_land(40.71, -74.01))    # New York
        self.assertTrue(is_land(-33.87, 151.21))   # Sydney
        self.assertFalse(is_land(0.0, -30.0))      # mid Atlantic
        self.assertFalse(is_land(30.0, -150.0))    # mid Pacific


class TestGraphs(unittest.TestCase):
    def test_bars_shape(self):
        lines = braille_bars([1, 2, 3, 4, 5] * 20, width=30, height=5)
        self.assertEqual(len(lines), 5)
        self.assertTrue(all(len(line) == 30 for line in lines))

    def test_bars_empty(self):
        lines = braille_bars([], width=10, height=3)
        self.assertEqual(len(lines), 3)

    def test_sparkline(self):
        self.assertEqual(len(sparkline([0, 1, 2, 3], width=10)), 4)

    def test_human(self):
        self.assertEqual(human_bytes(0), "0B")
        self.assertEqual(human_bytes(1536), "1.5KB")
        self.assertEqual(human_rate(1048576), "1.0MB/s")


class TestProcAggregation(unittest.TestCase):
    def setUp(self):
        from netmonguru.core.models import ProcNet
        from netmonguru.core.monitor import _demo_connections
        self.conns = [c for c in _demo_connections() if c.family == "IPv4"]
        self.procs = {
            "firefox.501": ProcNet(pid=501, name="firefox", bytes_in=1000,
                                   bytes_out=500, in_rate=2048.0,
                                   out_rate=512.0),
            "unknown.999": ProcNet(pid=999, name="ghost", bytes_in=7,
                                   bytes_out=7, in_rate=1.0, out_rate=1.0),
        }

    def test_grouping(self):
        from netmonguru.core.procs import aggregate
        rows = aggregate(self.conns, self.procs)
        by_name = {r.name: r for r in rows}
        self.assertEqual(by_name["firefox"].conns, 3)
        self.assertEqual(by_name["firefox"].established, 2)
        self.assertEqual(by_name["firefox"].remotes, 3)
        self.assertEqual(by_name["firefox"].in_rate, 2048.0)
        # listening sockets are captured with their ports
        self.assertIn(6379, by_name["redis-server"].listen_ports)
        # a nettop row with no matching socket still shows up
        self.assertIn("ghost", by_name)

    def test_sorted_by_traffic(self):
        from netmonguru.core.procs import aggregate
        rows = aggregate(self.conns, self.procs)
        self.assertEqual(rows[0].name, "firefox")


if __name__ == "__main__":
    unittest.main()
