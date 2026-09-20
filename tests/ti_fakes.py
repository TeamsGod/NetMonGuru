"""Canned upstream answers (shapes follow each provider's API docs)."""

import json

BAD = "185.220.101.7"          # in feeds + bad everywhere
GOOD = "142.250.203.110"

FEEDS = {
    "feodotracker": json.dumps([
        {"ip_address": BAD, "port": 443, "status": "online",
         "malware": "Emotet", "last_online": "2026-09-19"}]).encode(),
    "sslbl": b"# Firstseen,DstIP,DstPort\n2026-09-01 10:00:00,203.0.113.50,8443\n",
    "spamhaus": b"; Spamhaus DROP\n45.9.148.0/24 ; SBL1\n10.0.0.0/8 ; bogon\n",
    "emergingthreats": b"# comment\n198.51.100.23\n",
    "firehol": b"# level1\n0.0.0.0/8\n192.168.0.0/16\n91.92.240.0/22\n",
    "torproject": ("%s\n" % BAD).encode(),
    "urlhaus": b"# hostfile\n127.0.0.1\tmalware-cdn.example\n127.0.0.1\tbad.test\n",
    "threatfox-api": json.dumps({"query_status": "ok", "data": [
        {"ioc": "203.0.113.66:4444", "ioc_type": "ip:port",
         "threat_type": "botnet_cc", "malware_printable": "Cobalt Strike",
         "confidence_level": 100},
        {"ioc": "evil.example", "ioc_type": "domain"}]}).encode(),
}


def fetch(url, headers, body=None):
    for needle, payload in FEEDS.items():
        if needle in url:
            return payload
    raise OSError(f"unexpected feed url {url}")


def http(url, headers, body=None, timeout=10.0):
    bad = BAD in url or (body and BAD.encode() in body)
    if "abuseipdb" in url:
        assert headers.get("Key") == "k-abuse"
        return 200, json.dumps({"data": {
            "abuseConfidenceScore": 100 if bad else 0,
            "totalReports": 1342 if bad else 0, "numDistinctUsers": 311,
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example Hosting", "countryCode": "DE",
            "isTor": bad, "isWhitelisted": not bad}}).encode()
    if "virustotal.com/api/v3/ip_addresses" in url:
        return 200, json.dumps({"data": {"attributes": {
            "last_analysis_stats": {"malicious": 9 if bad else 0,
                                    "suspicious": 1 if bad else 0,
                                    "harmless": 60, "undetected": 20},
            "reputation": -40 if bad else 5, "as_owner": "Example", "asn": 64500,
            "last_analysis_results": {"EngineA": {"category": "malicious",
                                                  "result": "malware"}}
            if bad else {}}}}).encode()
    if "virustotal.com/api/v3/files" in url:
        return 404, b"{}"
    if "threatfox-api" in url:
        if bad:
            return 200, json.dumps({"query_status": "ok", "data": [{
                "ioc": f"{BAD}:443", "threat_type": "botnet_cc",
                "threat_type_desc": "C2", "malware_printable": "Emotet",
                "confidence_level": 90, "first_seen": "2026-09-01",
                "tags": ["emotet"]}]}).encode()
        return 200, b'{"query_status": "no_result", "data": "x"}'
    if "otx.alienvault" in url:
        n = 5 if bad else 0
        return 200, json.dumps({"pulse_info": {"count": n, "pulses": [
            {"name": f"Campaign {i}", "modified": "2026-09-10T00:00:00",
             "tags": ["c2"], "malware_families": [{"display_name": "Emotet"}]}
            for i in range(n)]}}).encode()
    if "greynoise" in url:
        if bad:
            return 200, json.dumps({"ip": BAD, "noise": True, "riot": False,
                                    "classification": "malicious",
                                    "name": "unknown",
                                    "last_seen": "2026-09-19"}).encode()
        return 200, json.dumps({"riot": True, "noise": False,
                                "classification": "benign",
                                "name": "Google"}).encode()
    if "rdap.org" in url:
        return 200, json.dumps({
            "handle": "NET-EX", "name": "EXAMPLE-NET", "country": "DE",
            "startAddress": "185.220.101.0", "endAddress": "185.220.101.255",
            "cidr0_cidrs": [{"v4prefix": "185.220.101.0", "length": 24}],
            "events": [{"eventAction": "registration",
                        "eventDate": "2017-05-02T10:00:00Z"}],
            "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                ["fn", {}, "text", "Abuse Desk"],
                ["email", {}, "text", "abuse@example.net"]]]}]}).encode()
    if "internetdb" in url:
        if bad:
            return 200, json.dumps({"ports": [22, 443, 9001],
                                    "tags": ["tor"], "vulns": ["CVE-2023-1"],
                                    "hostnames": ["exit.example.net"],
                                    "cpes": ["cpe:/a:openbsd:openssh"]}).encode()
        return 404, b"{}"
    if "crt.sh" in url:
        return 200, json.dumps([{"name_value": "a.example.net\nb.example.net",
                                 "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                                 "not_before": "2026-08-01T00:00:00"}]).encode()
    return 599, b"unexpected"


from netmonguru.core.ti_sources import set_vt_rate   # noqa: E402

set_vt_rate(100000)      # canned answers: never wait for a VirusTotal slot

KEYS = {"abuseipdb": "k-abuse", "virustotal": "k-vt", "abusech": "k-ach",
        "otx": "k-otx"}
