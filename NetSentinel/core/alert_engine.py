"""
alert_engine.py - Rule-based alert generation from extracted data.
"""

import time


class AlertEngine:
    """Generates alerts based on rules applied to extracted analysis data."""

    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"

    def __init__(self):
        self._alerts = []
        self._port_scan_tracker = {}   # ip -> {port_set, first_seen}
        self._icmp_tracker = {}        # ip -> {count, first_seen}
        self._ftp_fail_tracker = {}    # ip -> fail_count

    def process_packet(self, ts, raw):
        """Called per packet for rule evaluation needing raw packet data."""
        try:
            import dpkt
            import socket
            eth = dpkt.ethernet.Ethernet(raw)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                return

            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            # Port scan detection
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                tracker = self._port_scan_tracker.setdefault(src_ip, {"ports": set(), "first_seen": ts})
                if ts - tracker["first_seen"] > 5:
                    tracker["ports"].clear()
                    tracker["first_seen"] = ts
                tracker["ports"].add(tcp.dport)
                if len(tracker["ports"]) > 20:
                    self._add_alert(
                        ts, self.SEVERITY_HIGH, "Port Scan Detected",
                        f"{src_ip} contacted {len(tracker['ports'])} ports in 5 seconds.",
                        [src_ip, dst_ip],
                    )
                    tracker["ports"].clear()

            # ICMP flood detection
            if isinstance(ip.data, dpkt.icmp.ICMP):
                tracker = self._icmp_tracker.setdefault(src_ip, {"count": 0, "first_seen": ts})
                if ts - tracker["first_seen"] > 10:
                    tracker["count"] = 0
                    tracker["first_seen"] = ts
                tracker["count"] += 1
                if tracker["count"] > 100:
                    self._add_alert(
                        ts, self.SEVERITY_MEDIUM, "ICMP Flood Detected",
                        f"{src_ip} sent {tracker['count']} ICMP packets in 10 seconds.",
                        [src_ip],
                    )
                    tracker["count"] = 0

            # Non-standard port HTTP
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                payload = bytes(tcp.data)
                if payload and payload[:4] in (b"GET ", b"POST", b"HTTP"):
                    if tcp.dport not in (80, 443, 8080):
                        self._add_alert(
                            ts, self.SEVERITY_LOW, "Non-Standard Protocol Port",
                            f"HTTP traffic on port {tcp.dport} from {src_ip}.",
                            [src_ip, dst_ip],
                        )
        except Exception:
            pass

    def evaluate_credential(self, cred):
        """Rule 1: Cleartext credentials detected."""
        self._add_alert(
            cred["timestamp"], self.SEVERITY_HIGH, "Cleartext Credentials Detected",
            f"{cred['protocol']} credentials for user '{cred['username']}' captured "
            f"between {cred['src_ip']} and {cred['dst_ip']}.",
            [cred["src_ip"], cred["dst_ip"]],
        )

    def evaluate_dns(self, record):
        """Rule 2: Suspicious DNS."""
        tags = record.get("tags", [])
        if tags:
            tag_str = ", ".join(tags)
            self._add_alert(
                record["timestamp"], self.SEVERITY_MEDIUM, "Suspicious DNS Detected",
                f"Domain '{record['domain']}' triggered flags: {tag_str}.",
                [record["src_ip"]],
            )

    def evaluate_file(self, file_info):
        """Rule 4: Large file transfer; Rule 8: Malicious hash."""
        if file_info.get("size", 0) > 50 * 1024 * 1024:
            self._add_alert(
                file_info["timestamp"], self.SEVERITY_MEDIUM, "Large File Transfer Detected",
                f"File '{file_info['filename']}' ({file_info['size'] // (1024*1024)} MB) "
                f"transferred over {file_info['protocol']}.",
                [file_info["src_ip"], file_info.get("dst_ip", "")],
            )

        vt = file_info.get("vt_status", "")
        if vt and vt not in ("Pending", "Clean", "Error", ""):
            self._add_alert(
                file_info["timestamp"], self.SEVERITY_CRITICAL, "Known Malicious File Hash Detected",
                f"File '{file_info['filename']}' flagged by VirusTotal: {vt}.",
                [file_info["src_ip"]],
            )

    def evaluate_ftp_failure(self, src_ip, ts):
        """Rule 7: FTP brute force."""
        self._ftp_fail_tracker[src_ip] = self._ftp_fail_tracker.get(src_ip, 0) + 1
        if self._ftp_fail_tracker[src_ip] > 5:
            self._add_alert(
                ts, self.SEVERITY_HIGH, "FTP Brute Force Detected",
                f"{src_ip} had {self._ftp_fail_tracker[src_ip]} failed FTP login attempts.",
                [src_ip],
            )
            self._ftp_fail_tracker[src_ip] = 0

    def get_alerts(self):
        return list(self._alerts)

    def reset(self):
        self._alerts.clear()
        self._port_scan_tracker.clear()
        self._icmp_tracker.clear()
        self._ftp_fail_tracker.clear()

    def _add_alert(self, ts, severity, rule_name, description, ips):
        self._alerts.append({
            "timestamp": ts,
            "severity": severity,
            "rule_name": rule_name,
            "description": description,
            "related_ips": ips,
        })
