"""
filter_bar.py - Reusable real-time filter widget for tables.
"""

from PyQt5.QtWidgets import QWidget, QHBoxLayout, QLineEdit, QLabel, QPushButton
from PyQt5.QtCore import pyqtSignal, Qt


class FilterBar(QWidget):
    """Emits filter_changed(text) as the user types."""

    filter_changed = pyqtSignal(str)
    filter_cleared = pyqtSignal()

    def __init__(self, placeholder="Filter...", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self._label = QLabel("Filter:")
        self._label.setStyleSheet("color: #a0a0b0;")

        self._input = QLineEdit()
        self._input.setPlaceholderText(placeholder)
        self._input.setStyleSheet(
            "background: #16213e; color: #eaeaea; border: 1px solid #0f3460; "
            "border-radius: 3px; padding: 3px 6px;"
        )
        self._input.textChanged.connect(self._on_text_changed)

        self._clear_btn = QPushButton("✕")
        self._clear_btn.setFixedWidth(24)
        self._clear_btn.setStyleSheet(
            "background: #0f3460; color: #eaeaea; border: none; border-radius: 3px;"
        )
        self._clear_btn.clicked.connect(self._on_clear)

        layout.addWidget(self._label)
        layout.addWidget(self._input, stretch=1)
        layout.addWidget(self._clear_btn)

    def _on_text_changed(self, text):
        self.filter_changed.emit(text)

    def _on_clear(self):
        self._input.clear()
        self.filter_cleared.emit()

    def get_text(self):
        return self._input.text()
