"""
exporter.py - CSV, JSON and ZIP export logic.
"""

import csv
import json
import os
import zipfile
import datetime


class Exporter:
    """Exports analysis data to CSV, JSON, and ZIP formats."""

    def __init__(self, output_dir):
        self._output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def export_csv(self, name, data):
        """
        Export a list of dicts to a CSV file named <name>.csv.

        Args:
            name: File name stem (without extension).
            data: List of dicts to export.

        Returns:
            Full path of the written file.
        """
        if not data:
            return None

        path = os.path.join(self._output_dir, f"{name}.csv")
        fieldnames = list(data[0].keys())

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in data:
                # Sanitize non-serializable types
                clean = {k: self._to_str(v) for k, v in row.items()}
                writer.writerow(clean)
        return path

    def export_json(self, filename, data):
        """
        Export a nested data structure to a JSON file.

        Args:
            filename: Output file name (without directory).
            data: Dict or list to serialize.

        Returns:
            Full path of the written file.
        """
        path = os.path.join(self._output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=self._json_default)
        return path

    def export_zip(self, filename, file_infos):
        """
        Package all extracted files into a ZIP archive with a manifest.

        Args:
            filename: Name of the output ZIP file.
            file_infos: List of file info dicts (must have 'path' and 'filename').

        Returns:
            Full path of the ZIP file.
        """
        zip_path = os.path.join(self._output_dir, filename)
        manifest_rows = []

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for fi in file_infos:
                src_path = fi.get("path", "")
                if src_path and os.path.exists(src_path):
                    arc_name = fi.get("filename", os.path.basename(src_path))
                    zf.write(src_path, arc_name)
                    manifest_rows.append({
                        "filename": arc_name,
                        "md5": fi.get("md5", ""),
                        "size": fi.get("size", 0),
                        "protocol": fi.get("protocol", ""),
                        "src_ip": fi.get("src_ip", ""),
                        "mime_type": fi.get("mime_type", ""),
                    })

            # Write manifest CSV inside ZIP
            import io
            buf = io.StringIO()
            if manifest_rows:
                writer = csv.DictWriter(buf, fieldnames=list(manifest_rows[0].keys()))
                writer.writeheader()
                writer.writerows(manifest_rows)
            zf.writestr("manifest.csv", buf.getvalue())

        return zip_path

    @staticmethod
    def _to_str(v):
        if isinstance(v, (list, set)):
            return ", ".join(str(x) for x in v)
        if isinstance(v, float):
            # Timestamps
            if v > 1e9:
                try:
                    return datetime.datetime.fromtimestamp(v, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
        return str(v) if v is not None else ""

    @staticmethod
    def _json_default(obj):
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return obj.hex()
        return str(obj)
