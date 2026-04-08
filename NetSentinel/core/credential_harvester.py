"""
credential_harvester.py - Extracts plaintext credentials from TCP streams.
Supports FTP, HTTP Basic Auth, HTTP Form POST, Telnet, SMTP AUTH, POP3, IMAP.
"""

import base64
import re
import socket
import dpkt


class CredentialHarvester:
    """Passively extracts cleartext credentials from reassembled TCP streams."""

    # Common form field names for username / password
    USERNAME_FIELDS = re.compile(
        r"(?:username|user|login|email|uid|uname|account)", re.I
    )
    PASSWORD_FIELDS = re.compile(
        r"(?:password|passwd|pass|pwd|secret)", re.I
    )

    def __init__(self):
        self._credentials = []
        self._ftp_state = {}   # (src, dst, sport, dport) -> partial state
        self._telnet_state = {}
        self._smtp_state = {}

    def process_packet(self, ts, raw):
        try:
            eth = dpkt.ethernet.Ethernet(raw)
        except Exception:
            return

        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            return

        if not isinstance(ip.data, dpkt.tcp.TCP):
            return

        tcp = ip.data
        payload = bytes(tcp.data)
        if not payload:
            return

        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        sport = tcp.sport
        dport = tcp.dport

        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            text = ""

        # FTP
        if dport == 21 or sport == 21:
            self._parse_ftp(ts, src_ip, dst_ip, sport, dport, text)

        # HTTP
        if dport in (80, 8080, 8000) or sport in (80, 8080, 8000):
            self._parse_http(ts, src_ip, dst_ip, sport, dport, text)

        # Telnet
        if dport == 23 or sport == 23:
            self._parse_telnet(ts, src_ip, dst_ip, sport, dport, text)

        # SMTP AUTH
        if dport in (25, 587, 465) or sport in (25, 587, 465):
            self._parse_smtp(ts, src_ip, dst_ip, sport, dport, text)

        # POP3
        if dport == 110 or sport == 110:
            self._parse_pop3(ts, src_ip, dst_ip, sport, dport, text)

        # IMAP
        if dport == 143 or sport == 143:
            self._parse_imap(ts, src_ip, dst_ip, sport, dport, text)

    # ------------------------------------------------------------------
    # Protocol parsers
    # ------------------------------------------------------------------

    def _parse_ftp(self, ts, src_ip, dst_ip, sport, dport, text):
        key = (src_ip, dst_ip, sport, dport)
        if key not in self._ftp_state:
            self._ftp_state[key] = {}
        state = self._ftp_state[key]

        for line in text.splitlines():
            line = line.strip()
            upper = line.upper()
            if upper.startswith("USER "):
                state["username"] = line[5:].strip()
            elif upper.startswith("PASS "):
                password = line[5:].strip()
                username = state.get("username", "")
                self._add_credential(ts, "FTP", username, password, src_ip, dst_ip)
                state.clear()
            elif "530" in line:  # Login incorrect
                state["failed"] = state.get("failed", 0) + 1

    def _parse_http(self, ts, src_ip, dst_ip, sport, dport, text):
        lines = text.split("\r\n")
        if not lines:
            return

        # HTTP Basic Auth
        for line in lines:
            if line.lower().startswith("authorization: basic "):
                encoded = line[21:].strip()
                try:
                    decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
                    if ":" in decoded:
                        username, _, password = decoded.partition(":")
                        self._add_credential(ts, "HTTP Basic Auth", username, password, src_ip, dst_ip)
                except Exception:
                    pass

        # HTTP Form POST
        if lines[0].startswith("POST "):
            body = text.split("\r\n\r\n", 1)
            if len(body) == 2:
                self._parse_form_body(ts, src_ip, dst_ip, body[1])

    def _parse_form_body(self, ts, src_ip, dst_ip, body):
        """Parse URL-encoded POST body for credentials."""
        username = None
        password = None
        try:
            from urllib.parse import parse_qs, unquote_plus
            params = parse_qs(body, keep_blank_values=True)
            for k, v in params.items():
                if self.USERNAME_FIELDS.search(k):
                    username = unquote_plus(v[0]) if v else ""
                elif self.PASSWORD_FIELDS.search(k):
                    password = unquote_plus(v[0]) if v else ""
            if username or password:
                self._add_credential(ts, "HTTP Form POST", username or "", password or "", src_ip, dst_ip)
        except Exception:
            pass

    def _parse_telnet(self, ts, src_ip, dst_ip, sport, dport, text):
        """Reconstruct telnet keystrokes - very basic heuristic."""
        key = (src_ip, dst_ip, sport, dport)
        if key not in self._telnet_state:
            self._telnet_state[key] = {"stage": "user", "buf": ""}
        state = self._telnet_state[key]

        # Strip IAC negotiation bytes
        cleaned = re.sub(r"[\xff][\xfb-\xfe].", "", text)
        printable = "".join(c for c in cleaned if c.isprintable() or c in "\r\n")

        for char in printable:
            if char in "\r\n":
                line = state["buf"].strip()
                if line:
                    if state["stage"] == "user":
                        state["username"] = line
                        state["stage"] = "pass"
                    elif state["stage"] == "pass":
                        self._add_credential(ts, "Telnet", state.get("username", ""), line, src_ip, dst_ip)
                        state["stage"] = "user"
                        state["buf"] = ""
                        return
                state["buf"] = ""
            else:
                state["buf"] += char

    def _parse_smtp(self, ts, src_ip, dst_ip, sport, dport, text):
        key = (src_ip, dst_ip, sport, dport)
        if key not in self._smtp_state:
            self._smtp_state[key] = {}
        state = self._smtp_state[key]

        for line in text.splitlines():
            line = line.strip()
            upper = line.upper()
            if upper.startswith("AUTH LOGIN"):
                state["stage"] = "user_b64"
            elif state.get("stage") == "user_b64":
                try:
                    state["username"] = base64.b64decode(line).decode("utf-8", errors="replace")
                    state["stage"] = "pass_b64"
                except Exception:
                    state.clear()
            elif state.get("stage") == "pass_b64":
                try:
                    password = base64.b64decode(line).decode("utf-8", errors="replace")
                    self._add_credential(ts, "SMTP AUTH", state.get("username", ""), password, src_ip, dst_ip)
                    state.clear()
                except Exception:
                    state.clear()

    def _parse_pop3(self, ts, src_ip, dst_ip, sport, dport, text):
        key = (src_ip, dst_ip, sport, dport)
        if key not in self._ftp_state:
            self._ftp_state[key] = {}
        state = self._ftp_state[key]
        # POP3 uses same USER/PASS as FTP
        self._parse_ftp_like(ts, "POP3", src_ip, dst_ip, state, text)

    def _parse_imap(self, ts, src_ip, dst_ip, sport, dport, text):
        for line in text.splitlines():
            m = re.search(r'LOGIN\s+"?([^" ]+)"?\s+"?([^" \r\n]+)"?', line, re.I)
            if m:
                self._add_credential(ts, "IMAP", m.group(1), m.group(2), src_ip, dst_ip)

    def _parse_ftp_like(self, ts, proto, src_ip, dst_ip, state, text):
        for line in text.splitlines():
            line = line.strip()
            upper = line.upper()
            if upper.startswith("USER "):
                state["username"] = line[5:].strip()
            elif upper.startswith("PASS "):
                password = line[5:].strip()
                self._add_credential(ts, proto, state.get("username", ""), password, src_ip, dst_ip)
                state.clear()

    # ------------------------------------------------------------------

    def _add_credential(self, ts, protocol, username, password, src_ip, dst_ip):
        self._credentials.append({
            "timestamp": ts,
            "protocol": protocol,
            "username": username,
            "password": password,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        })

    def get_credentials(self):
        return list(self._credentials)

    def reset(self):
        self._credentials.clear()
        self._ftp_state.clear()
        self._telnet_state.clear()
        self._smtp_state.clear()
