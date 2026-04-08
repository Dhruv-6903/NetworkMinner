"""
host_extractor.py - Extracts host inventory from network traffic.
Captures IP, MAC, hostname, OS guess, GeoIP, ports, bytes sent/received.
"""

import socket
import struct
import dpkt


class HostExtractor:
    """Builds a host inventory from packet data."""

    # Passive OS fingerprinting table: (ttl, window_size) -> OS guess
    OS_FINGERPRINTS = {
        (64, 5840): "Linux",
        (64, 65535): "macOS / iOS",
        (128, 8192): "Windows",
        (255, 4128): "Cisco IOS",
    }

    def __init__(self):
        self._hosts = {}  # ip_str -> host_dict

    def process_packet(self, ts, raw):
        """Dispatch a raw packet for host extraction."""
        try:
            eth = dpkt.ethernet.Ethernet(raw)
        except Exception:
            return

        if not isinstance(eth.data, dpkt.ip.IP):
            # Try IPv6
            if isinstance(eth.data, dpkt.ip6.IP6):
                self._process_ip6(ts, eth)
            return

        ip = eth.data
        src_ip = self._ip_to_str(ip.src)
        dst_ip = self._ip_to_str(ip.dst)
        src_mac = self._mac_to_str(eth.src)
        dst_mac = self._mac_to_str(eth.dst)

        self._update_host(src_ip, src_mac, ts, len(raw), 0)
        self._update_host(dst_ip, dst_mac, ts, 0, len(raw))

        # TCP window / TTL fingerprinting
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            self._fingerprint_os(src_ip, ip.ttl, tcp.win)
            # Extract port as open port for destination
            self._add_port(dst_ip, tcp.dport)
            self._add_port(src_ip, tcp.sport)
            # TLS SNI
            if tcp.dport == 443 or tcp.sport == 443:
                sni = self._extract_tls_sni(bytes(tcp.data))
                if sni:
                    self._add_hostname(dst_ip, sni)

        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            self._add_port(dst_ip, udp.dport)
            # NetBIOS name
            if udp.dport == 137 or udp.sport == 137:
                name = self._extract_netbios_name(bytes(udp.data))
                if name:
                    self._add_hostname(src_ip, name)

        # HTTP Host header
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            if tcp.dport in (80, 8080, 8000):
                host_hdr = self._extract_http_host(bytes(tcp.data))
                if host_hdr:
                    self._add_hostname(dst_ip, host_hdr)

    def _process_ip6(self, ts, eth):
        ip6 = eth.data
        src_ip = socket.inet_ntop(socket.AF_INET6, ip6.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip6.dst)
        self._update_host(src_ip, self._mac_to_str(eth.src), ts, len(bytes(eth)), 0)
        self._update_host(dst_ip, self._mac_to_str(eth.dst), ts, 0, len(bytes(eth)))

    def _update_host(self, ip, mac, ts, bytes_sent, bytes_recv):
        if ip not in self._hosts:
            self._hosts[ip] = {
                "ip": ip,
                "mac": mac,
                "hostnames": set(),
                "os_guess": "Unknown",
                "country": "",
                "city": "",
                "asn": "",
                "org": "",
                "first_seen": ts,
                "last_seen": ts,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "ports": set(),
            }
        host = self._hosts[ip]
        if mac and mac != "00:00:00:00:00:00" and host["mac"] == "00:00:00:00:00:00":
            host["mac"] = mac
        host["last_seen"] = ts
        host["bytes_sent"] += bytes_sent
        host["bytes_recv"] += bytes_recv

    def _fingerprint_os(self, ip, ttl, win):
        if ip not in self._hosts:
            return
        # Normalize TTL to common values
        for ttl_val in (64, 128, 255):
            if ttl <= ttl_val:
                normalized_ttl = ttl_val
                break
        else:
            normalized_ttl = ttl

        guess = self.OS_FINGERPRINTS.get((normalized_ttl, win))
        if guess and self._hosts[ip]["os_guess"] == "Unknown":
            self._hosts[ip]["os_guess"] = guess

    def _add_hostname(self, ip, hostname):
        if ip in self._hosts and hostname:
            self._hosts[ip]["hostnames"].add(hostname.lower().strip())

    def _add_port(self, ip, port):
        if ip in self._hosts and port:
            self._hosts[ip]["ports"].add(port)

    def enrich_geoip(self, geoip_reader):
        """Enrich all hosts with GeoIP data using a geoip2 reader."""
        for ip, host in self._hosts.items():
            try:
                resp = geoip_reader.city(ip)
                host["country"] = resp.country.name or ""
                host["city"] = resp.city.name or ""
                host["asn"] = ""
                host["org"] = ""
            except Exception:
                pass

    def get_hosts(self):
        """Return list of host dicts with serializable fields."""
        result = []
        for h in self._hosts.values():
            d = dict(h)
            d["hostnames"] = list(h["hostnames"])
            d["ports"] = sorted(h["ports"])
            result.append(d)
        return result

    def get_host(self, ip):
        h = self._hosts.get(ip)
        if not h:
            return None
        d = dict(h)
        d["hostnames"] = list(h["hostnames"])
        d["ports"] = sorted(h["ports"])
        return d

    def reset(self):
        self._hosts.clear()

    # ------------------------------------------------------------------
    # Helper / static methods
    # ------------------------------------------------------------------

    @staticmethod
    def _ip_to_str(b):
        try:
            return socket.inet_ntoa(b)
        except Exception:
            return "0.0.0.0"

    @staticmethod
    def _mac_to_str(b):
        try:
            return ":".join(f"{x:02x}" for x in b)
        except Exception:
            return "00:00:00:00:00:00"

    @staticmethod
    def _extract_tls_sni(data):
        """Extract the SNI from a TLS ClientHello."""
        try:
            if len(data) < 5:
                return None
            if data[0] != 0x16:  # TLS handshake
                return None
            # Skip TLS record header (5 bytes)
            pos = 5
            if data[pos] != 0x01:  # ClientHello
                return None
            pos += 4  # handshake type + length
            pos += 2  # version
            pos += 32  # random
            session_len = data[pos]
            pos += 1 + session_len
            cipher_len = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2 + cipher_len
            comp_len = data[pos]
            pos += 1 + comp_len
            if pos + 2 > len(data):
                return None
            ext_total = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            end = pos + ext_total
            while pos + 4 <= end:
                ext_type = struct.unpack("!H", data[pos:pos+2])[0]
                ext_len = struct.unpack("!H", data[pos+2:pos+4])[0]
                pos += 4
                if ext_type == 0:  # SNI
                    # server_name_list_length (2) + name_type (1) + name_length (2)
                    name_len = struct.unpack("!H", data[pos+3:pos+5])[0]
                    return data[pos+5:pos+5+name_len].decode("utf-8", errors="ignore")
                pos += ext_len
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_netbios_name(data):
        """Extract the NetBIOS name from a NBNS packet."""
        try:
            if len(data) < 13:
                return None
            # Encoded name starts at byte 13
            encoded = data[13:13+32]
            name = ""
            for i in range(0, 32, 2):
                c = ((encoded[i] - 0x41) << 4) | (encoded[i+1] - 0x41)
                if c == 0x20:
                    break
                name += chr(c)
            return name.strip() if name.strip() else None
        except Exception:
            return None

    @staticmethod
    def _extract_http_host(data):
        """Extract HTTP Host header value."""
        try:
            text = data.decode("utf-8", errors="ignore")
            for line in text.split("\r\n"):
                if line.lower().startswith("host:"):
                    return line.split(":", 1)[1].strip().split(":")[0]
        except Exception:
            pass
        return None
