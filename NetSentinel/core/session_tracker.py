"""
session_tracker.py - TCP and UDP flow reconstruction.
Sessions keyed by 5-tuple for O(1) lookup.
"""

import socket
import dpkt
import time


# Port -> application protocol mapping
PORT_PROTOCOLS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 162: "SNMP", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP", 8443: "HTTPS", 27017: "MongoDB",
}

MAX_STREAM_BUFFER = 10 * 1024 * 1024  # 10 MB cap per stream


class SessionTracker:
    """Tracks TCP/UDP sessions and reassembles TCP streams."""

    def __init__(self):
        self._sessions = {}   # 5-tuple -> session_dict
        self._streams = {}    # 5-tuple -> bytearray (TCP payload buffer)

    def process_packet(self, ts, raw):
        try:
            eth = dpkt.ethernet.Ethernet(raw)
        except Exception:
            return

        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            proto_num = ip.p
        elif isinstance(ip, dpkt.ip6.IP6):
            src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
            proto_num = ip.nxt
        else:
            return

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            self._handle_tcp(ts, src_ip, dst_ip, tcp, len(raw))
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            self._handle_udp(ts, src_ip, dst_ip, udp, len(raw))
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            self._handle_icmp(ts, src_ip, dst_ip, len(raw))

    def _handle_tcp(self, ts, src_ip, dst_ip, tcp, pkt_len):
        key = (src_ip, tcp.sport, dst_ip, tcp.dport, "TCP")
        rev_key = (dst_ip, tcp.dport, src_ip, tcp.sport, "TCP")

        # Normalize to canonical direction
        canon_key = min(key, rev_key)
        is_forward = (key == canon_key)

        flags = tcp.flags
        syn = bool(flags & dpkt.tcp.TH_SYN)
        fin = bool(flags & dpkt.tcp.TH_FIN)
        rst = bool(flags & dpkt.tcp.TH_RST)

        if canon_key not in self._sessions:
            app_proto = self._guess_protocol(tcp.sport, tcp.dport, "TCP")
            self._sessions[canon_key] = {
                "src_ip": canon_key[0], "src_port": canon_key[1],
                "dst_ip": canon_key[2], "dst_port": canon_key[3],
                "protocol": "TCP",
                "app_protocol": app_proto,
                "start_time": ts, "end_time": ts,
                "bytes_fwd": 0, "bytes_rev": 0,
                "flags": set(),
                "state": "SYN_SEEN" if syn else "ESTABLISHED",
            }
            self._streams[canon_key] = bytearray()

        sess = self._sessions[canon_key]
        sess["end_time"] = ts

        if is_forward:
            sess["bytes_fwd"] += pkt_len
        else:
            sess["bytes_rev"] += pkt_len

        for flag_name, flag_val in [("SYN", dpkt.tcp.TH_SYN), ("FIN", dpkt.tcp.TH_FIN),
                                     ("RST", dpkt.tcp.TH_RST), ("ACK", dpkt.tcp.TH_ACK)]:
            if flags & flag_val:
                sess["flags"].add(flag_name)

        if fin or rst:
            sess["state"] = "CLOSED"

        # Append payload to stream buffer
        payload = bytes(tcp.data)
        if payload:
            buf = self._streams[canon_key]
            if len(buf) + len(payload) <= MAX_STREAM_BUFFER:
                buf.extend(payload)

    def _handle_udp(self, ts, src_ip, dst_ip, udp, pkt_len):
        key = (src_ip, udp.sport, dst_ip, udp.dport, "UDP")
        rev_key = (dst_ip, udp.dport, src_ip, udp.sport, "UDP")
        canon_key = min(key, rev_key)
        is_forward = (key == canon_key)

        if canon_key not in self._sessions:
            app_proto = self._guess_protocol(udp.sport, udp.dport, "UDP")
            self._sessions[canon_key] = {
                "src_ip": canon_key[0], "src_port": canon_key[1],
                "dst_ip": canon_key[2], "dst_port": canon_key[3],
                "protocol": "UDP",
                "app_protocol": app_proto,
                "start_time": ts, "end_time": ts,
                "bytes_fwd": 0, "bytes_rev": 0,
                "flags": set(),
                "state": "ACTIVE",
            }
            self._streams[canon_key] = bytearray()

        sess = self._sessions[canon_key]
        sess["end_time"] = ts

        payload = bytes(udp.data)
        if payload:
            buf = self._streams[canon_key]
            if len(buf) + len(payload) <= MAX_STREAM_BUFFER:
                buf.extend(payload)

        if is_forward:
            sess["bytes_fwd"] += pkt_len
        else:
            sess["bytes_rev"] += pkt_len

    def _handle_icmp(self, ts, src_ip, dst_ip, pkt_len):
        key = (src_ip, 0, dst_ip, 0, "ICMP")
        if key not in self._sessions:
            self._sessions[key] = {
                "src_ip": src_ip, "src_port": 0,
                "dst_ip": dst_ip, "dst_port": 0,
                "protocol": "ICMP",
                "app_protocol": "ICMP",
                "start_time": ts, "end_time": ts,
                "bytes_fwd": pkt_len, "bytes_rev": 0,
                "flags": set(),
                "state": "ACTIVE",
            }
        else:
            self._sessions[key]["end_time"] = ts
            self._sessions[key]["bytes_fwd"] += pkt_len

    def get_sessions(self):
        result = []
        for key, sess in self._sessions.items():
            d = dict(sess)
            d["flags"] = list(sess["flags"])
            d["duration"] = sess["end_time"] - sess["start_time"]
            result.append(d)
        return result

    def get_stream(self, src_ip, src_port, dst_ip, dst_port, proto="TCP"):
        key = (src_ip, src_port, dst_ip, dst_port, proto)
        rev_key = (dst_ip, dst_port, src_ip, src_port, proto)
        canon = min(key, rev_key)
        buf = self._streams.get(canon)
        if buf:
            return bytes(buf)
        return b""

    def reset(self):
        self._sessions.clear()
        self._streams.clear()

    @staticmethod
    def _guess_protocol(sport, dport, proto):
        for port in (dport, sport):
            if port in PORT_PROTOCOLS:
                return PORT_PROTOCOLS[port]
        return proto
