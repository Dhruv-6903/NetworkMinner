"""
live_capture.py - Handles live interface sniffing using Scapy's AsyncSniffer.
Runs inside a QThread and emits packets via a callback.
"""

import queue
import threading
import time


class LiveCapture:
    """
    Wraps Scapy AsyncSniffer for live packet capture.
    Packets are buffered and flushed via a callback every FLUSH_INTERVAL seconds.
    """

    BUFFER_SIZE = 100
    FLUSH_INTERVAL = 0.5  # seconds

    def __init__(self, packet_callback=None):
        """
        Args:
            packet_callback: Callable(list[bytes]) called with buffered raw packets.
        """
        self._packet_callback = packet_callback
        self._sniffer = None
        self._buffer = []
        self._lock = threading.Lock()
        self._flush_thread = None
        self._running = False

    @staticmethod
    def list_interfaces():
        """Return list of available network interface names."""
        try:
            from scapy.arch import get_if_list
            return get_if_list()
        except Exception:
            return []

    def start(self, interface, bpf_filter=""):
        """Start capturing on the given interface."""
        try:
            from scapy.sendrecv import AsyncSniffer
            from scapy.packet import Raw

            self._running = True
            self._buffer = []

            self._sniffer = AsyncSniffer(
                iface=interface,
                filter=bpf_filter if bpf_filter else None,
                prn=self._on_packet,
                store=False,
            )
            self._sniffer.start()

            self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
            self._flush_thread.start()
        except Exception as e:
            raise RuntimeError(f"Failed to start live capture: {e}") from e

    def stop(self):
        """Stop the sniffer and flush remaining packets."""
        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        # Flush remaining buffer
        self._flush_buffer()

    def _on_packet(self, pkt):
        """Scapy callback - convert to raw bytes and buffer."""
        try:
            raw = bytes(pkt)
            ts = time.time()
            with self._lock:
                self._buffer.append((ts, raw))
        except Exception:
            pass

    def _flush_loop(self):
        """Periodically flush the buffer to the callback."""
        while self._running:
            time.sleep(self.FLUSH_INTERVAL)
            self._flush_buffer()

    def _flush_buffer(self):
        with self._lock:
            if not self._buffer:
                return
            batch = list(self._buffer)
            self._buffer.clear()

        if self._packet_callback and batch:
            try:
                self._packet_callback(batch)
            except Exception:
                pass

    @staticmethod
    def is_root():
        """Check if the process is running with root/admin privileges."""
        import os
        import sys
        if sys.platform == "win32":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0
