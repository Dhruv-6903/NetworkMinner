"""
file_extractor.py - Reconstructs files transferred over HTTP, FTP-DATA, TFTP, SMTP, SMB.
Saves files to output/extracted_files/.
"""

import gzip
import hashlib
import io
import os
import re
import socket
import dpkt


class FileExtractor:
    """Extracts transferred files from reassembled TCP/UDP streams."""

    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output", "extracted_files")

    def __init__(self, output_dir=None):
        self._output_dir = output_dir or self.OUTPUT_DIR
        os.makedirs(self._output_dir, exist_ok=True)
        self._extracted = []
        self._http_streams = {}   # (src_ip, src_port, dst_ip, dst_port) -> bytearray
        self._tftp_data = {}      # (src_ip, dst_ip, block) -> bytearray

    def process_packet(self, ts, raw):
        try:
            eth = dpkt.ethernet.Ethernet(raw)
        except Exception:
            return

        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            return

        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            payload = bytes(tcp.data)
            if not payload:
                return
            sport, dport = tcp.sport, tcp.dport

            # HTTP response detection (port 80 / 8080 from server side)
            if sport in (80, 8080, 8000) or dport in (80, 8080, 8000):
                key = (src_ip, sport, dst_ip, dport)
                buf = self._http_streams.setdefault(key, bytearray())
                buf.extend(payload)
                self._try_extract_http(ts, src_ip, dst_ip, key)

        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            payload = bytes(udp.data)
            sport, dport = udp.sport, udp.dport

            # TFTP DATA packets (opcode 3)
            if sport == 69 or dport == 69 or (sport > 1024 and len(payload) > 4):
                self._try_tftp(ts, src_ip, dst_ip, payload)

    def _try_extract_http(self, ts, src_ip, dst_ip, key):
        """Attempt to extract a complete HTTP response from buffer."""
        buf = self._http_streams.get(key)
        if not buf:
            return

        data = bytes(buf)
        # Find HTTP response header
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            return

        header_bytes = data[:header_end]
        body_bytes = data[header_end + 4:]

        try:
            header_text = header_bytes.decode("utf-8", errors="replace")
        except Exception:
            return

        lines = header_text.split("\r\n")
        if not lines or not lines[0].startswith("HTTP/"):
            return

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        content_length = int(headers.get("content-length", -1))
        if content_length > 0 and len(body_bytes) < content_length:
            return  # Not fully received yet

        # Dechunk if needed
        transfer_enc = headers.get("transfer-encoding", "")
        if "chunked" in transfer_enc:
            body_bytes = self._dechunk(body_bytes)

        # Decompress if gzip
        content_enc = headers.get("content-encoding", "")
        if "gzip" in content_enc:
            try:
                body_bytes = gzip.decompress(body_bytes)
            except Exception:
                pass

        # Determine filename
        filename = self._extract_filename(headers)
        if not filename:
            return

        mime_type = headers.get("content-type", "application/octet-stream").split(";")[0].strip()
        saved_path = self._save_file(filename, body_bytes)
        if saved_path:
            md5 = hashlib.md5(body_bytes).hexdigest()
            self._extracted.append({
                "timestamp": ts,
                "filename": filename,
                "protocol": "HTTP",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "mime_type": mime_type,
                "size": len(body_bytes),
                "md5": md5,
                "path": saved_path,
                "vt_status": "Pending",
            })
            # Clear buffer after extraction
            self._http_streams[key] = bytearray()

    def _try_tftp(self, ts, src_ip, dst_ip, payload):
        """Parse TFTP DATA opcode (3) packets."""
        try:
            if len(payload) < 4:
                return
            opcode = int.from_bytes(payload[:2], "big")
            if opcode == 3:  # DATA
                block = int.from_bytes(payload[2:4], "big")
                data = payload[4:]
                key = (src_ip, dst_ip)
                buf = self._tftp_data.setdefault(key, bytearray())
                buf.extend(data)
                if len(data) < 512:  # Last block
                    body = bytes(buf)
                    filename = f"tftp_{src_ip}_{block}.bin"
                    saved = self._save_file(filename, body)
                    if saved:
                        md5 = hashlib.md5(body).hexdigest()
                        self._extracted.append({
                            "timestamp": ts,
                            "filename": filename,
                            "protocol": "TFTP",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "mime_type": "application/octet-stream",
                            "size": len(body),
                            "md5": md5,
                            "path": saved,
                            "vt_status": "Pending",
                        })
                    del self._tftp_data[key]
        except Exception:
            pass

    def _save_file(self, filename, data):
        """Write data to the output directory, return saved path or None."""
        try:
            safe_name = re.sub(r"[^\w.\-]", "_", os.path.basename(filename))
            if not safe_name:
                safe_name = "unknown_file"
            # Avoid overwriting: append index if needed
            dest = os.path.join(self._output_dir, safe_name)
            index = 1
            while os.path.exists(dest):
                base, ext = os.path.splitext(safe_name)
                dest = os.path.join(self._output_dir, f"{base}_{index}{ext}")
                index += 1
            with open(dest, "wb") as f:
                f.write(data)
            return dest
        except Exception:
            return None

    def get_extracted_files(self):
        return list(self._extracted)

    def reset(self):
        self._extracted.clear()
        self._http_streams.clear()
        self._tftp_data.clear()

    @staticmethod
    def _dechunk(data):
        """Decode HTTP chunked transfer encoding."""
        result = bytearray()
        buf = io.BytesIO(data)
        while True:
            line = buf.readline().strip()
            if not line:
                break
            try:
                chunk_size = int(line, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            result.extend(buf.read(chunk_size))
            buf.read(2)  # CRLF after chunk
        return bytes(result)

    @staticmethod
    def _extract_filename(headers):
        """Try to extract a useful filename from HTTP headers."""
        # Content-Disposition: attachment; filename="foo.txt"
        cd = headers.get("content-disposition", "")
        m = re.search(r'filename[*]?=["\']?([^"\';\r\n]+)', cd, re.I)
        if m:
            return m.group(1).strip().strip('"\'')

        # Infer from content-type
        ct = headers.get("content-type", "")
        ext_map = {
            "application/pdf": ".pdf",
            "application/zip": ".zip",
            "application/x-gzip": ".gz",
            "image/jpeg": ".jpg",
            "image/png": ".png",
            "image/gif": ".gif",
            "text/html": ".html",
            "text/plain": ".txt",
            "application/octet-stream": ".bin",
            "application/x-executable": ".exe",
            "application/x-msdownload": ".exe",
        }
        for mime, ext in ext_map.items():
            if mime in ct:
                return f"extracted_file{ext}"

        return None
