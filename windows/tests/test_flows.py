"""nettop full-listing parser, per-connection rates and histories."""

import unittest

from netmonguru.core.bandwidth import (ProcessNetCollector, _endpoint,
                                       flow_key, parse_nettop,
                                       parse_nettop_full)

# layout of current macOS: timestamp first, label second
FULL = """time,,bytes_in,bytes_out,
16:41:16.735506,firefox.501,1048576,262144,
16:41:16.735510,tcp4 192.168.1.24:51344<->142.250.203.110:443,1000000,200000,
16:41:16.735512,tcp6 2a00:1450:401b::200e.51360<->2606:4700::6810:85e5.443,48576,62144,
16:41:16.735520,mDNSResponder.508,4096,2048,
16:41:16.735521,udp4 *:5353<->*:*,4096,2048,
16:41:16.735530,Microsoft Teams.503,52428800,1048576,
16:41:16.735531,udp6 fe80::1%en0.62000<->fe80::2%en0.3478,100,200,
"""

LATER = FULL.replace("1048576,262144", "3145728,362144") \
            .replace("1000000,200000", "3000000,300000")


class TestParser(unittest.TestCase):
    def test_timestamp_column_is_not_mistaken_for_a_process(self):
        procs, _ = parse_nettop_full(FULL)
        self.assertEqual(set(procs), {"firefox.501", "mDNSResponder.508",
                                      "Microsoft Teams.503"})
        self.assertEqual(procs["firefox.501"], (501, "firefox", 1048576,
                                                262144))
        self.assertEqual(parse_nettop(FULL), procs)

    def test_flows_belong_to_the_process_row_above(self):
        _, flows = parse_nettop_full(FULL)
        self.assertEqual(len(flows), 4)
        f = flows[flow_key("TCP", "192.168.1.24", 51344,
                           "142.250.203.110", 443)]
        self.assertEqual((f.pid, f.pname, f.bytes_in), (501, "firefox",
                                                        1000000))
        v6 = flows[flow_key("TCP", "2a00:1450:401b::200e", 51360,
                            "2606:4700::6810:85e5", 443)]
        self.assertEqual((v6.family, v6.pid), ("IPv6", 501))
        teams = [x for x in flows.values() if x.pid == 503][0]
        self.assertEqual((teams.laddr, teams.lport, teams.raddr, teams.rport),
                         ("fe80::1", 62000, "fe80::2", 3478))

    def test_endpoints(self):
        self.assertEqual(_endpoint("1.2.3.4:443"), ("1.2.3.4", 443))
        self.assertEqual(_endpoint("*:*"), ("", 0))
        self.assertEqual(_endpoint("*:5353"), ("", 5353))
        self.assertEqual(_endpoint("::1.8080"), ("::1", 8080))

    def test_per_process_only_output_still_parses(self):
        procs, flows = parse_nettop_full(
            "time,,bytes_in,bytes_out,\nfirefox.501,,10,20,\n")
        self.assertEqual((procs["firefox.501"][2], flows), (10, {}))


class TestRates(unittest.TestCase):
    def test_rates_history_and_pruning(self):
        c = ProcessNetCollector(enabled=False)
        c.ingest(*parse_nettop_full(FULL), now=100.0)
        procs = c.ingest(*parse_nettop_full(LATER), now=102.0)
        self.assertEqual(procs["firefox.501"].in_rate, (3145728 - 1048576) / 2)
        key = flow_key("TCP", "192.168.1.24", 51344, "142.250.203.110", 443)
        self.assertEqual(c.flows[key].in_rate, 1000000.0)
        self.assertEqual(c.flows[key].out_rate, 50000.0)
        self.assertEqual(c.flow_history(key), ([0.0, 1000000.0],
                                               [0.0, 50000.0]))
        self.assertEqual(c.proc_history("firefox.501")[0][-1], 1048576.0)

        gone = "\n".join(l for l in LATER.splitlines() if "51344" not in l)
        c.ingest(*parse_nettop_full(gone), now=104.0)
        self.assertNotIn(key, c.flows)
        self.assertEqual(c.flow_history(key), ([], []))

    def test_counter_reset_never_gives_negative_rates(self):
        c = ProcessNetCollector(enabled=False)
        c.ingest(*parse_nettop_full(LATER), now=1.0)
        procs = c.ingest(*parse_nettop_full(FULL), now=2.0)
        self.assertEqual(procs["firefox.501"].in_rate, 0)


if __name__ == "__main__":
    unittest.main()
