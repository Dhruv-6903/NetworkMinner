"""
dns_parser.py - DNS query and response parsing with suspicious activity detection.
"""

import math
import socket
import dpkt


class DNSParser:
    """Parses DNS packets and flags suspicious activity."""

    BEACONING_THRESHOLD = 10   # same domain queried more than N times

    def __init__(self):
        self._records = []
        self._query_counts = {}   # domain -> count

    def process_packet(self, ts, raw):
        try:
            eth = dpkt.ethernet.Ethernet(raw)
        except Exception:
            return

        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):
            src_ip = socket.inet_ntoa(ip.src)
        elif isinstance(ip, dpkt.ip6.IP6):
            src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
        else:
            return

        if not isinstance(ip.data, dpkt.udp.UDP):
            return

        udp = ip.data
        if udp.dport != 53 and udp.sport != 53:
            return

        try:
            dns = dpkt.dns.DNS(bytes(udp.data))
        except Exception:
            return

        is_response = bool(dns.qr)

        for q in dns.qn:
            domain = q.name.rstrip(".").lower()
            qtype = self._qtype_name(q.type)

            # Count queries for beaconing detection
            self._query_counts[domain] = self._query_counts.get(domain, 0) + 1

            answers = []
            if is_response:
                for an in dns.an:
                    answers.append(self._rdata_str(an))

            tags = self._analyze(domain, qtype, is_response, dns)

            record = {
                "timestamp": ts,
                "src_ip": src_ip,
                "domain": domain,
                "query_type": qtype,
                "answers": answers,
                "is_response": is_response,
                "nxdomain": is_response and dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN,
                "tags": tags,
            }
            self._records.append(record)

    def _analyze(self, domain, qtype, is_response, dns):
        tags = []

        # Long subdomain -> possible DNS tunneling
        label = domain.split(".")[0] if "." in domain else domain
        if len(label) > 50:
            tags.append("DNS_TUNNELING")

        # High-entropy label -> possible DGA
        if self._shannon_entropy(label) > 3.5:
            tags.append("HIGH_ENTROPY_DGA")

        # Beaconing
        if self._query_counts.get(domain, 0) > self.BEACONING_THRESHOLD:
            tags.append("BEACONING")

        # NXDomain
        if is_response and dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN:
            tags.append("NXDOMAIN")

        # TXT record abuse
        if qtype == "TXT":
            tags.append("TXT_RECORD")

        return tags

    def get_records(self):
        return list(self._records)

    def reset(self):
        self._records.clear()
        self._query_counts.clear()

    @staticmethod
    def _shannon_entropy(s):
        if not s:
            return 0.0
        n = len(s)
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _qtype_name(qtype):
        mapping = {
            1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
            12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
            33: "SRV", 255: "ANY",
        }
        return mapping.get(qtype, str(qtype))

    @staticmethod
    def _rdata_str(rr):
        try:
            if isinstance(rr, dpkt.dns.DNS.RR):
                rdata = rr.rdata
                if rr.type == 1 and len(rdata) == 4:
                    return socket.inet_ntoa(rdata)
                if rr.type == 28 and len(rdata) == 16:
                    return socket.inet_ntop(socket.AF_INET6, rdata)
                if rr.type == 5:
                    return rr.cname.rstrip(".")
                if rr.type == 12:
                    return rr.ptrname.rstrip(".")
                return rdata.decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""
