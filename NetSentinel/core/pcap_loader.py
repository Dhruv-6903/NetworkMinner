"""
pcap_loader.py - Handles PCAP and PCAPNG file reading using dpkt.
Single-pass architecture: each packet is dispatched to all extractors in one loop.
"""

import dpkt
import struct


class PCAPLoader:
    """Loads a PCAP/PCAPNG file and dispatches packets to registered extractors."""

    def __init__(self):
        self._extractors = []

    def register_extractor(self, extractor):
        """Register an extractor that has a process_packet(ts, raw) method."""
        self._extractors.append(extractor)

    def load(self, filepath, progress_callback=None):
        """
        Read the PCAP file in a single pass and dispatch each packet.

        Args:
            filepath: Path to .pcap or .pcapng file.
            progress_callback: Callable(count) called every 1000 packets.

        Returns:
            Total packet count processed.
        """
        count = 0
        try:
            with open(filepath, "rb") as f:
                # Detect PCAPNG by magic bytes
                magic = f.read(4)
                f.seek(0)
                if magic == b"\x0a\x0d\x0d\x0a":
                    reader = self._pcapng_reader(f)
                else:
                    reader = dpkt.pcap.Reader(f)

                for ts, raw in reader:
                    for extractor in self._extractors:
                        try:
                            extractor.process_packet(ts, raw)
                        except Exception:
                            pass
                    count += 1
                    if progress_callback and count % 1000 == 0:
                        progress_callback(count)

        except Exception as e:
            raise RuntimeError(f"Failed to load PCAP: {e}") from e

        if progress_callback:
            progress_callback(count)
        return count

    @staticmethod
    def _pcapng_reader(f):
        """Minimal PCAPNG reader that yields (timestamp, raw_packet) tuples."""
        try:
            import dpkt.pcapng as pcapng_module
            reader = pcapng_module.Reader(f)
            for ts, raw in reader:
                yield ts, raw
        except Exception:
            # Fallback: try dpkt.pcap on the same file handle
            f.seek(0)
            try:
                reader = dpkt.pcap.Reader(f)
                for ts, raw in reader:
                    yield ts, raw
            except Exception:
                return

    def get_file_info(self, filepath):
        """Return basic info about a PCAP file without loading all packets."""
        info = {"filepath": filepath, "packet_count": 0, "format": "unknown"}
        try:
            with open(filepath, "rb") as f:
                magic = f.read(4)
                f.seek(0)
                if magic == b"\x0a\x0d\x0d\x0a":
                    info["format"] = "pcapng"
                else:
                    info["format"] = "pcap"
                # Count packets cheaply
                if info["format"] == "pcap":
                    reader = dpkt.pcap.Reader(f)
                    for _ in reader:
                        info["packet_count"] += 1
        except Exception:
            pass
        return info
