"""
threat_intel.py - VirusTotal API v3 and GeoIP lookups.
VirusTotal requests are rate-limited to 4 per minute (15s delay between batches).
"""

import hashlib
import queue
import threading
import time

import requests


class ThreatIntelWorker:
    """
    Background worker that processes VirusTotal hash lookup requests.
    Rate-limited to 4 req/min (free tier).
    Calls result_callback(md5, result_str) when each lookup completes.
    """

    VT_URL = "https://www.virustotal.com/api/v3/files/{}"
    DELAY_BETWEEN_REQUESTS = 15  # seconds (4 req/min free tier)

    def __init__(self, api_key_provider, result_callback=None):
        """
        Args:
            api_key_provider: Callable that returns the current VT API key string.
            result_callback: Callable(md5, result_str).
        """
        self._api_key_provider = api_key_provider
        self._result_callback = result_callback
        self._queue = queue.Queue()
        self._thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._thread.start()

    def submit(self, md5):
        """Queue an MD5 hash for VT lookup."""
        self._queue.put(md5)

    def _worker_loop(self):
        while True:
            md5 = self._queue.get()
            if md5 is None:
                break
            result = self._lookup(md5)
            if self._result_callback:
                try:
                    self._result_callback(md5, result)
                except Exception:
                    pass
            time.sleep(self.DELAY_BETWEEN_REQUESTS)

    def _lookup(self, md5):
        api_key = self._api_key_provider()
        if not api_key:
            return "Error: No API key"
        try:
            resp = requests.get(
                self.VT_URL.format(md5),
                headers={"x-apikey": api_key},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                if malicious == 0:
                    return "Clean"
                return f"{malicious}/{total} engines"
            elif resp.status_code == 404:
                return "Not found"
            elif resp.status_code == 403:
                return "Error: Invalid API key"
            else:
                return f"Error: HTTP {resp.status_code}"
        except Exception as e:
            return f"Error: {e}"

    def stop(self):
        self._queue.put(None)


class GeoIPLookup:
    """GeoIP enrichment using MaxMind GeoLite2 database (offline)."""

    def __init__(self, db_path=None):
        self._reader = None
        if db_path:
            self.load(db_path)

    def load(self, db_path):
        """Load the GeoLite2-City.mmdb database."""
        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(db_path)
        except Exception as e:
            self._reader = None
            raise RuntimeError(f"Failed to load GeoIP database: {e}") from e

    def lookup(self, ip):
        """
        Return dict with country, city, asn, org for the given IP.
        Returns empty dict if unavailable.
        """
        if not self._reader:
            return {}
        try:
            resp = self._reader.city(ip)
            return {
                "country": resp.country.name or "",
                "city": resp.city.name or "",
                "asn": "",
                "org": "",
            }
        except Exception:
            return {}

    def is_loaded(self):
        return self._reader is not None

    def close(self):
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
