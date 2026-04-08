"""
status_bar.py - Live stats bar at the bottom of the main window.
"""

from PyQt5.QtWidgets import QStatusBar, QLabel, QProgressBar
from PyQt5.QtCore import Qt


class StatusBar(QStatusBar):
    """Shows packet count, host count, alert count and a progress bar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            "QStatusBar { background: #0f3460; color: #eaeaea; }"
            "QStatusBar::item { border: none; }"
        )

        self._packets_lbl = QLabel("Packets: 0")
        self._hosts_lbl = QLabel("Hosts: 0")
        self._alerts_lbl = QLabel("Alerts: 0")
        self._progress = QProgressBar()
        self._progress.setMaximumWidth(200)
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setStyleSheet(
            "QProgressBar { background: #16213e; border: 1px solid #0f3460; "
            "border-radius: 3px; text-align: center; color: #eaeaea; }"
            "QProgressBar::chunk { background: #e94560; }"
        )

        for lbl in (self._packets_lbl, self._hosts_lbl, self._alerts_lbl):
            lbl.setStyleSheet("color: #eaeaea; padding: 0 8px;")
            self.addWidget(lbl)

        self.addPermanentWidget(self._progress)

    def update_stats(self, packets=None, hosts=None, alerts=None, progress=None):
        if packets is not None:
            self._packets_lbl.setText(f"Packets: {packets:,}")
        if hosts is not None:
            self._hosts_lbl.setText(f"Hosts: {hosts}")
        if alerts is not None:
            self._alerts_lbl.setText(f"Alerts: {alerts}")
        if progress is not None:
            self._progress.setValue(int(progress))

    def reset(self):
        self._packets_lbl.setText("Packets: 0")
        self._hosts_lbl.setText("Hosts: 0")
        self._alerts_lbl.setText("Alerts: 0")
        self._progress.setValue(0)
