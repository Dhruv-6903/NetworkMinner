"""
settings.py - Persistent user preferences stored in a JSON file.
"""

import json
import os


SETTINGS_DIR = os.path.join(os.path.expanduser("~"), ".netsentinel")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")

DEFAULTS = {
    "vt_api_key": "",
    "geoip_db_path": "",
    "output_dir": "",
    "mask_passwords": False,
    "column_widths": {},
    "theme": "dark",
}


class Settings:
    """Loads and saves user preferences to ~/.netsentinel/settings.json."""

    def __init__(self):
        self._data = dict(DEFAULTS)
        self._load()

    def _load(self):
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    stored = json.load(f)
                self._data.update(stored)
        except Exception:
            pass

    def save(self):
        try:
            os.makedirs(SETTINGS_DIR, exist_ok=True)
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except Exception:
            pass

    def get(self, key, default=None):
        return self._data.get(key, default if default is not None else DEFAULTS.get(key))

    def set(self, key, value):
        self._data[key] = value

    def all(self):
        return dict(self._data)
