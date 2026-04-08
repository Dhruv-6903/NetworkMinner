"""
main_window.py - NetSentinel main application window.
Manages toolbar, tab container, workers and signal wiring.
"""

import os
import sys
import time

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QToolBar, QAction, QFileDialog, QComboBox, QLabel,
    QTabWidget, QSplitter, QPushButton, QDialog,
    QFormLayout, QLineEdit, QCheckBox, QDialogButtonBox,
    QMenu, QMessageBox, QApplication
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings
from PyQt5.QtGui import QIcon, QFont

from .tabs.hosts_tab import HostsTab
from .tabs.sessions_tab import SessionsTab
from .tabs.credentials_tab import CredentialsTab
from .tabs.files_tab import FilesTab
from .tabs.dns_tab import DNSTab
from .tabs.alerts_tab import AlertsTab
from .widgets.status_bar import StatusBar

from ..core.pcap_loader import PCAPLoader
from ..core.host_extractor import HostExtractor
from ..core.session_tracker import SessionTracker
from ..core.credential_harvester import CredentialHarvester
from ..core.dns_parser import DNSParser
from ..core.file_extractor import FileExtractor
from ..core.alert_engine import AlertEngine
from ..core.live_capture import LiveCapture
from ..core.threat_intel import ThreatIntelWorker, GeoIPLookup
from ..output.exporter import Exporter
from ..config.settings import Settings


class AnalysisWorker(QThread):
    """Worker thread for PCAP parsing and live capture dispatch."""

    packet_parsed = pyqtSignal(int)
    host_found = pyqtSignal(dict)
    session_updated = pyqtSignal(dict)
    credential_found = pyqtSignal(dict)
    dns_record_found = pyqtSignal(dict)
    file_found = pyqtSignal(dict)
    alert_found = pyqtSignal(dict)
    progress_updated = pyqtSignal(int)
    analysis_complete = pyqtSignal()

    def __init__(self, filepath=None, parent=None):
        super().__init__(parent)
        self.filepath = filepath
        self._stop = False

        # Create extractors
        self.host_extractor = HostExtractor()
        self.session_tracker = SessionTracker()
        self.credential_harvester = CredentialHarvester()
        self.dns_parser = DNSParser()
        self.file_extractor = FileExtractor()
        self.alert_engine = AlertEngine()

    def run(self):
        loader = PCAPLoader()
        loader.register_extractor(self.host_extractor)
        loader.register_extractor(self.session_tracker)
        loader.register_extractor(self.credential_harvester)
        loader.register_extractor(self.dns_parser)
        loader.register_extractor(self.file_extractor)
        loader.register_extractor(self.alert_engine)

        packet_count = [0]
        last_emit = [time.time()]

        def progress_cb(count):
            packet_count[0] = count
            now = time.time()
            if now - last_emit[0] >= 0.5:
                self._emit_buffered_data()
                last_emit[0] = now
            self.packet_parsed.emit(count)

        try:
            loader.load(self.filepath, progress_callback=progress_cb)
        except Exception as e:
            pass

        # Emit all remaining data
        self._emit_buffered_data()
        self.analysis_complete.emit()

    def _emit_buffered_data(self):
        for host in self.host_extractor.get_hosts():
            self.host_found.emit(host)
        for sess in self.session_tracker.get_sessions():
            self.session_updated.emit(sess)
        for cred in self.credential_harvester.get_credentials():
            self.credential_found.emit(cred)
        for record in self.dns_parser.get_records():
            self.dns_record_found.emit(record)
        for fi in self.file_extractor.get_extracted_files():
            self.file_found.emit(fi)

        # Evaluate alerts for new credentials and DNS
        for cred in self.credential_harvester.get_credentials():
            self.alert_engine.evaluate_credential(cred)
        for record in self.dns_parser.get_records():
            if record.get("tags"):
                self.alert_engine.evaluate_dns(record)
        for fi in self.file_extractor.get_extracted_files():
            self.alert_engine.evaluate_file(fi)

        for alert in self.alert_engine.get_alerts():
            self.alert_found.emit(alert)

    def stop(self):
        self._stop = True


class MainWindow(QMainWindow):
    """NetSentinel main application window."""

    APP_NAME = "NetSentinel"
    TAGLINE = "Passive network forensics, actively working for you."

    def __init__(self):
        super().__init__()
        self._settings = Settings()
        self._worker = None
        self._vt_worker = None
        self._live_capture = LiveCapture()
        self._geoip = GeoIPLookup()
        self._emitted_hosts = set()
        self._emitted_sessions = set()
        self._emitted_creds = 0
        self._emitted_dns = 0
        self._emitted_files = 0
        self._emitted_alerts = 0

        self._setup_ui()
        self._load_settings()
        self._init_geoip()
        self._init_vt_worker()

        # UI refresh timer (buffered updates every 500ms)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(500)
        self._refresh_timer.timeout.connect(self._flush_worker_data)

    def _setup_ui(self):
        self.setWindowTitle(f"{self.APP_NAME} — {self.TAGLINE}")
        self.resize(1400, 850)
        self.setMinimumSize(900, 600)

        self._apply_stylesheet()

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self._build_toolbar()
        self._build_interface_bar(main_layout)
        self._build_tab_area(main_layout)
        self._build_status_bar()

    def _apply_stylesheet(self):
        qss_path = os.path.join(os.path.dirname(__file__), "styles", "theme.qss")
        if os.path.exists(qss_path):
            with open(qss_path, "r") as f:
                self.setStyleSheet(f.read())
        else:
            self.setStyleSheet(
                "QMainWindow, QWidget { background-color: #1a1a2e; color: #eaeaea; }"
            )

    def _build_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setStyleSheet(
            "QToolBar { background: #16213e; border-bottom: 1px solid #0f3460; padding: 4px; }"
            "QToolButton { color: #eaeaea; padding: 4px 10px; }"
            "QToolButton:hover { background: #0f3460; border-radius: 3px; }"
        )
        self.addToolBar(toolbar)

        # App title
        title_lbl = QLabel(f"  {self.APP_NAME}  ")
        title_lbl.setFont(QFont("Arial", 14, QFont.Bold))
        title_lbl.setStyleSheet("color: #e94560;")
        toolbar.addWidget(title_lbl)

        toolbar.addSeparator()

        # Load PCAP
        self._load_action = QAction("📂 Load PCAP", self)
        self._load_action.setToolTip("Load a .pcap or .pcapng file")
        self._load_action.triggered.connect(self._on_load_pcap)
        toolbar.addAction(self._load_action)

        # Start / Stop capture
        self._start_action = QAction("▶ Start Capture", self)
        self._start_action.triggered.connect(self._on_start_capture)
        toolbar.addAction(self._start_action)

        self._stop_action = QAction("■ Stop", self)
        self._stop_action.triggered.connect(self._on_stop)
        self._stop_action.setEnabled(False)
        toolbar.addAction(self._stop_action)

        toolbar.addSeparator()

        # Export
        self._export_btn = QPushButton("⬇ Export")
        self._export_btn.setStyleSheet(
            "QPushButton { background: #0f3460; color: #eaeaea; border: none; "
            "border-radius: 3px; padding: 4px 12px; }"
            "QPushButton:hover { background: #e94560; }"
        )
        self._export_btn.clicked.connect(self._on_export)
        toolbar.addWidget(self._export_btn)

        # Settings
        self._settings_action = QAction("⚙ Settings", self)
        self._settings_action.triggered.connect(self._on_settings)
        toolbar.addAction(self._settings_action)

        # Disable live capture if not root on Linux
        if sys.platform != "win32" and not LiveCapture.is_root():
            self._start_action.setEnabled(False)
            self._start_action.setToolTip("Root privileges required for live capture")

    def _build_interface_bar(self, parent_layout):
        bar = QWidget()
        bar.setStyleSheet("background: #16213e; border-bottom: 1px solid #0f3460;")
        h = QHBoxLayout(bar)
        h.setContentsMargins(8, 4, 8, 4)

        iface_lbl = QLabel("Interface:")
        iface_lbl.setStyleSheet("color: #a0a0b0;")

        self._iface_combo = QComboBox()
        self._iface_combo.setStyleSheet(
            "QComboBox { background: #1a1a2e; color: #eaeaea; border: 1px solid #0f3460; "
            "border-radius: 3px; padding: 2px 6px; min-width: 150px; }"
        )
        self._populate_interfaces()

        filter_lbl = QLabel("Filter:")
        filter_lbl.setStyleSheet("color: #a0a0b0;")

        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("BPF filter expression...")
        self._filter_input.setStyleSheet(
            "QLineEdit { background: #1a1a2e; color: #eaeaea; border: 1px solid #0f3460; "
            "border-radius: 3px; padding: 2px 6px; }"
        )

        self._apply_filter_btn = QPushButton("Apply")
        self._apply_filter_btn.setStyleSheet(
            "QPushButton { background: #0f3460; color: #eaeaea; border: none; "
            "border-radius: 3px; padding: 3px 10px; }"
        )

        h.addWidget(iface_lbl)
        h.addWidget(self._iface_combo)
        h.addSpacing(16)
        h.addWidget(filter_lbl)
        h.addWidget(self._filter_input, stretch=1)
        h.addWidget(self._apply_filter_btn)

        parent_layout.addWidget(bar)

    def _build_tab_area(self, parent_layout):
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(
            "QTabWidget::pane { border: 0; background: #1a1a2e; }"
            "QTabBar::tab { background: #16213e; color: #a0a0b0; padding: 6px 14px; "
            "border: 1px solid #0f3460; border-bottom: none; margin-right: 2px; }"
            "QTabBar::tab:selected { background: #1a1a2e; color: #eaeaea; "
            "border-top: 2px solid #e94560; }"
            "QTabBar::tab:hover { color: #eaeaea; }"
        )

        self._hosts_tab = HostsTab()
        self._sessions_tab = SessionsTab()
        self._credentials_tab = CredentialsTab()
        self._files_tab = FilesTab()
        self._dns_tab = DNSTab()
        self._alerts_tab = AlertsTab()

        self._tabs.addTab(self._hosts_tab, "Hosts")
        self._tabs.addTab(self._sessions_tab, "Sessions")
        self._tabs.addTab(self._credentials_tab, "Credentials")
        self._tabs.addTab(self._files_tab, "Files")
        self._tabs.addTab(self._dns_tab, "DNS")
        self._tabs.addTab(self._alerts_tab, "Alerts  🔴0")

        # Wire stream getter
        from ..core.session_tracker import SessionTracker as ST
        self._sessions_tab.set_stream_getter(self._get_stream)

        # Alert count badge
        self._alerts_tab.alert_count_changed.connect(self._update_alert_badge)

        parent_layout.addWidget(self._tabs, stretch=1)

    def _build_status_bar(self):
        self._status_bar = StatusBar(self)
        self.setStatusBar(self._status_bar)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _on_load_pcap(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP File", "",
            "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if not path:
            return
        self._reset_all()
        self._start_analysis_worker(path)

    def _start_analysis_worker(self, filepath):
        self._worker = AnalysisWorker(filepath=filepath)
        self._worker.packet_parsed.connect(self._on_packet_count)
        self._worker.analysis_complete.connect(self._on_analysis_done)
        self._worker.start()
        self._refresh_timer.start()
        self._stop_action.setEnabled(True)
        self._load_action.setEnabled(False)
        self._status_bar.update_stats(progress=0)

    def _on_start_capture(self):
        iface = self._iface_combo.currentText()
        if not iface:
            QMessageBox.warning(self, "No Interface", "Please select a network interface.")
            return
        self._reset_all()
        bpf = self._filter_input.text().strip()

        def on_packets(batch):
            if self._worker:
                for ts, raw in batch:
                    for extractor in [
                        self._worker.host_extractor,
                        self._worker.session_tracker,
                        self._worker.credential_harvester,
                        self._worker.dns_parser,
                        self._worker.file_extractor,
                        self._worker.alert_engine,
                    ]:
                        try:
                            extractor.process_packet(ts, raw)
                        except Exception:
                            pass

        self._worker = AnalysisWorker()
        self._worker.filepath = None
        self._refresh_timer.start()

        try:
            self._live_capture = LiveCapture(packet_callback=on_packets)
            self._live_capture.start(iface, bpf)
        except Exception as e:
            QMessageBox.critical(self, "Capture Error", str(e))
            return

        self._stop_action.setEnabled(True)
        self._start_action.setEnabled(False)

    def _on_stop(self):
        if self._worker:
            self._worker.stop()
        try:
            self._live_capture.stop()
        except Exception:
            pass
        self._refresh_timer.stop()
        self._flush_worker_data()
        self._stop_action.setEnabled(False)
        self._start_action.setEnabled(True)
        self._load_action.setEnabled(True)

    def _on_analysis_done(self):
        self._refresh_timer.stop()
        self._flush_worker_data()
        self._status_bar.update_stats(progress=100)
        self._stop_action.setEnabled(False)
        self._load_action.setEnabled(True)

    def _on_packet_count(self, count):
        self._status_bar.update_stats(packets=count)

    def _on_export(self):
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background: #16213e; color: #eaeaea; }"
                           "QMenu::item:selected { background: #e94560; }")
        menu.addAction("Export CSV (all tabs)").triggered.connect(self._export_csv)
        menu.addAction("Export JSON report").triggered.connect(self._export_json)
        menu.addAction("Export extracted files (ZIP)").triggered.connect(self._export_zip)
        menu.exec_(self.mapToGlobal(self._export_btn.pos()))

    def _export_csv(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Export Folder")
        if not folder:
            return
        exp = Exporter(folder)
        exp.export_csv("Hosts", self._hosts_tab.get_data())
        exp.export_csv("Sessions", self._sessions_tab.get_data())
        exp.export_csv("Credentials", self._credentials_tab.get_data())
        exp.export_csv("DNS", self._dns_tab.get_data())
        exp.export_csv("Alerts", self._alerts_tab.get_data())
        QMessageBox.information(self, "Export", f"CSV files exported to:\n{folder}")

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON Report", "report.json", "JSON (*.json)")
        if not path:
            return
        exp = Exporter(os.path.dirname(path))
        exp.export_json(os.path.basename(path), {
            "hosts": self._hosts_tab.get_data(),
            "sessions": self._sessions_tab.get_data(),
            "credentials": self._credentials_tab.get_data(),
            "dns": self._dns_tab.get_data(),
            "alerts": self._alerts_tab.get_data(),
            "files": self._files_tab.get_data(),
        })
        QMessageBox.information(self, "Export", f"JSON report saved to:\n{path}")

    def _export_zip(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save ZIP Archive", "extracted_files.zip", "ZIP (*.zip)")
        if not path:
            return
        exp = Exporter(os.path.dirname(path))
        exp.export_zip(os.path.basename(path), self._files_tab.get_data())
        QMessageBox.information(self, "Export", f"ZIP archive saved to:\n{path}")

    def _on_settings(self):
        dlg = SettingsDialog(self._settings, self)
        if dlg.exec_() == QDialog.Accepted:
            self._settings.save()
            self._credentials_tab.set_mask_passwords(
                self._settings.get("mask_passwords", False)
            )
            self._init_geoip()
            self._init_vt_worker()

    # ------------------------------------------------------------------
    # Data flushing from worker
    # ------------------------------------------------------------------

    def _flush_worker_data(self):
        if not self._worker:
            return
        try:
            hosts = self._worker.host_extractor.get_hosts()
            for h in hosts:
                ip = h["ip"]
                if ip not in self._emitted_hosts:
                    self._emitted_hosts.add(ip)
                    # GeoIP enrich
                    if self._geoip.is_loaded():
                        geo = self._geoip.lookup(ip)
                        h.update(geo)
                    self._hosts_tab.add_host(h)
                else:
                    # Update existing
                    if self._geoip.is_loaded():
                        geo = self._geoip.lookup(ip)
                        h.update(geo)
                    self._hosts_tab.add_host(h)

            sessions = self._worker.session_tracker.get_sessions()
            new_sessions = sessions[len(self._emitted_sessions):]
            for s in new_sessions:
                self._sessions_tab.add_session(s)
            if new_sessions:
                self._emitted_sessions = set(range(len(sessions)))

            creds = self._worker.credential_harvester.get_credentials()
            for cred in creds[self._emitted_creds:]:
                self._credentials_tab.add_credential(cred)
                self._worker.alert_engine.evaluate_credential(cred)
            self._emitted_creds = len(creds)

            dns_records = self._worker.dns_parser.get_records()
            for rec in dns_records[self._emitted_dns:]:
                self._dns_tab.add_record(rec)
                if rec.get("tags"):
                    self._worker.alert_engine.evaluate_dns(rec)
            self._emitted_dns = len(dns_records)

            files = self._worker.file_extractor.get_extracted_files()
            for fi in files[self._emitted_files:]:
                self._files_tab.add_file(fi)
                self._worker.alert_engine.evaluate_file(fi)
                if self._vt_worker and fi.get("md5"):
                    self._vt_worker.submit(fi["md5"])
            self._emitted_files = len(files)

            alerts = self._worker.alert_engine.get_alerts()
            for al in alerts[self._emitted_alerts:]:
                self._alerts_tab.add_alert(al)
            self._emitted_alerts = len(alerts)

            self._status_bar.update_stats(
                hosts=len(self._emitted_hosts),
                alerts=self._alerts_tab.count(),
            )
            self._update_tab_badges()
        except Exception:
            pass

    def _update_tab_badges(self):
        counts = [
            len(self._emitted_hosts),
            len(self._emitted_sessions),
            self._emitted_creds,
            self._emitted_files,
            self._emitted_dns,
            self._alerts_tab.count(),
        ]
        labels = ["Hosts", "Sessions", "Credentials", "Files", "DNS", "Alerts"]
        for i, (lbl, cnt) in enumerate(zip(labels, counts)):
            if i == 5:  # Alerts tab with red badge
                self._tabs.setTabText(i, f"{lbl}  🔴{cnt}")
            else:
                self._tabs.setTabText(i, f"{lbl} {cnt}" if cnt else lbl)

    def _update_alert_badge(self, count):
        self._tabs.setTabText(5, f"Alerts  🔴{count}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_stream(self, src_ip, sport, dst_ip, dport, proto):
        if self._worker:
            return self._worker.session_tracker.get_stream(src_ip, sport, dst_ip, dport, proto)
        return b""

    def _reset_all(self):
        self._hosts_tab.clear()
        self._sessions_tab.clear()
        self._credentials_tab.clear()
        self._files_tab.clear()
        self._dns_tab.clear()
        self._alerts_tab.clear()
        self._status_bar.reset()
        self._emitted_hosts.clear()
        self._emitted_sessions.clear()
        self._emitted_creds = 0
        self._emitted_dns = 0
        self._emitted_files = 0
        self._emitted_alerts = 0
        if self._worker:
            self._worker.stop()
            self._worker = None
        self._update_tab_badges()

    def _populate_interfaces(self):
        try:
            ifaces = LiveCapture.list_interfaces()
            for iface in ifaces:
                self._iface_combo.addItem(iface)
        except Exception:
            pass

    def _init_geoip(self):
        db_path = self._settings.get("geoip_db_path", "")
        if db_path and os.path.exists(db_path):
            try:
                self._geoip.load(db_path)
            except Exception:
                pass

    def _init_vt_worker(self):
        def key_provider():
            return self._settings.get("vt_api_key", "")

        def vt_result(md5, status):
            self._files_tab.update_vt_status(md5, status)

        if self._vt_worker:
            try:
                self._vt_worker.stop()
            except Exception:
                pass
        self._vt_worker = ThreatIntelWorker(key_provider, result_callback=vt_result)

    def _load_settings(self):
        mask = self._settings.get("mask_passwords", False)
        self._credentials_tab.set_mask_passwords(mask)

    def closeEvent(self, event):
        if self._worker:
            self._worker.stop()
        if self._vt_worker:
            self._vt_worker.stop()
        self._settings.save()
        event.accept()


# ------------------------------------------------------------------
# Settings Dialog
# ------------------------------------------------------------------

class SettingsDialog(QDialog):
    """Dialog for configuring VT API key, GeoIP DB path and preferences."""

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.resize(480, 280)
        self.setStyleSheet(
            "QDialog { background: #1a1a2e; color: #eaeaea; }"
            "QLabel { color: #eaeaea; }"
            "QLineEdit { background: #16213e; color: #eaeaea; border: 1px solid #0f3460; "
            "border-radius: 3px; padding: 3px 6px; }"
            "QCheckBox { color: #eaeaea; }"
            "QPushButton { background: #0f3460; color: #eaeaea; border: none; "
            "border-radius: 3px; padding: 4px 12px; }"
            "QPushButton:hover { background: #e94560; }"
        )
        self._settings = settings
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._vt_key = QLineEdit(self._settings.get("vt_api_key", ""))
        self._vt_key.setEchoMode(QLineEdit.Password)
        self._vt_key.setPlaceholderText("VirusTotal API key")
        form.addRow("VT API Key:", self._vt_key)

        geoip_row = QHBoxLayout()
        self._geoip_path = QLineEdit(self._settings.get("geoip_db_path", ""))
        self._geoip_path.setPlaceholderText("Path to GeoLite2-City.mmdb")
        geoip_browse = QPushButton("Browse")
        geoip_browse.clicked.connect(self._browse_geoip)
        geoip_row.addWidget(self._geoip_path)
        geoip_row.addWidget(geoip_browse)
        form.addRow("GeoIP DB:", geoip_row)

        output_row = QHBoxLayout()
        self._output_dir = QLineEdit(self._settings.get("output_dir", ""))
        self._output_dir.setPlaceholderText("Output / extracted files folder")
        out_browse = QPushButton("Browse")
        out_browse.clicked.connect(self._browse_output)
        output_row.addWidget(self._output_dir)
        output_row.addWidget(out_browse)
        form.addRow("Output Dir:", output_row)

        self._mask_cb = QCheckBox("Mask passwords in Credentials tab")
        self._mask_cb.setChecked(self._settings.get("mask_passwords", False))

        layout.addLayout(form)
        layout.addWidget(self._mask_cb)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.setStyleSheet("QPushButton { min-width: 70px; }")
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_geoip(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select GeoIP DB", "", "MMDB (*.mmdb);;All (*)")
        if path:
            self._geoip_path.setText(path)

    def _browse_output(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if folder:
            self._output_dir.setText(folder)

    def _on_accept(self):
        self._settings.set("vt_api_key", self._vt_key.text())
        self._settings.set("geoip_db_path", self._geoip_path.text())
        self._settings.set("output_dir", self._output_dir.text())
        self._settings.set("mask_passwords", self._mask_cb.isChecked())
        self.accept()
