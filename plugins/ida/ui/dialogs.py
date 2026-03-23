from __future__ import annotations

from dataclasses import asdict

from PyQt5.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QVBoxLayout,
)

from core.compare import CompareRequest
from core.config import PluginConfig
from core.indexing import IndexRequest


class ConfigDialog(QDialog):
    def __init__(self, plugin_config: PluginConfig, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Binlex Config")
        self.setMinimumWidth(480)

        self.index_root = QLineEdit(plugin_config.index_root)
        self.default_corpus = QLineEdit(plugin_config.default_corpus)

        self.default_threads = QSpinBox()
        self.default_threads.setRange(1, 128)
        self.default_threads.setValue(plugin_config.default_threads)

        self.default_dimensions = QSpinBox()
        self.default_dimensions.setRange(1, 4096)
        self.default_dimensions.setValue(plugin_config.default_embedding_dimensions)

        self.default_compare_limit = QSpinBox()
        self.default_compare_limit.setRange(1, 256)
        self.default_compare_limit.setValue(plugin_config.default_compare_limit)

        self.default_index_blocks = QCheckBox("Index blocks when indexing functions")
        self.default_index_blocks.setChecked(plugin_config.default_index_blocks_with_functions)

        self.include_names = QCheckBox("Record meaningful function names")
        self.include_names.setChecked(plugin_config.include_meaningful_names)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("Index Root", self.index_root)
        form.addRow("Default Corpus", self.default_corpus)
        form.addRow("Default Threads", self.default_threads)
        form.addRow("Default Embedding Dimensions", self.default_dimensions)
        form.addRow("Default Compare Limit", self.default_compare_limit)
        form.addRow("", self.default_index_blocks)
        form.addRow("", self.include_names)
        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def value(self) -> PluginConfig:
        return PluginConfig(
            index_root=self.index_root.text().strip(),
            default_corpus=self.default_corpus.text().strip() or "default",
            default_threads=self.default_threads.value(),
            default_embedding_dimensions=self.default_dimensions.value(),
            default_compare_limit=self.default_compare_limit.value(),
            default_index_blocks_with_functions=self.default_index_blocks.isChecked(),
            include_meaningful_names=self.include_names.isChecked(),
        )


class IndexDialog(QDialog):
    def __init__(self, title: str, plugin_config: PluginConfig, *, allow_index_blocks: bool, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)

        self.corpus = QLineEdit(plugin_config.default_corpus)

        self.threads = QSpinBox()
        self.threads.setRange(1, 128)
        self.threads.setValue(plugin_config.default_threads)

        self.dimensions = QSpinBox()
        self.dimensions.setRange(1, 4096)
        self.dimensions.setValue(plugin_config.default_embedding_dimensions)

        self.index_blocks = QCheckBox("Index blocks too")
        self.index_blocks.setChecked(plugin_config.default_index_blocks_with_functions)
        self.index_blocks.setEnabled(allow_index_blocks)

        self.include_names = QCheckBox("Record meaningful function names")
        self.include_names.setChecked(plugin_config.include_meaningful_names)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("Corpus", self.corpus)
        form.addRow("Threads", self.threads)
        form.addRow("Embedding Dimensions", self.dimensions)
        if allow_index_blocks:
            form.addRow("", self.index_blocks)
        form.addRow("", self.include_names)
        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def value(self) -> IndexRequest:
        return IndexRequest(
            corpus=self.corpus.text().strip() or "default",
            threads=self.threads.value(),
            dimensions=self.dimensions.value(),
            index_blocks=self.index_blocks.isChecked() and self.index_blocks.isEnabled(),
            include_names=self.include_names.isChecked(),
        )


class CompareDialog(QDialog):
    def __init__(self, title: str, plugin_config: PluginConfig, available_corpora: list[str], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)

        self.corpora = QLineEdit(plugin_config.default_corpus)
        self.limit = QSpinBox()
        self.limit.setRange(1, 256)
        self.limit.setValue(plugin_config.default_compare_limit)

        layout = QVBoxLayout(self)
        if available_corpora:
            layout.addWidget(QLabel(f"Available corpora: {', '.join(sorted(available_corpora))}"))

        form = QFormLayout()
        form.addRow("Corpora", self.corpora)
        form.addRow("Result Limit", self.limit)
        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def value(self) -> CompareRequest:
        corpora = [item.strip() for item in self.corpora.text().split(",") if item.strip()]
        return CompareRequest(
            corpora=corpora or ["default"],
            limit=self.limit.value(),
        )


def show_error(message: str, parent=None) -> None:
    QMessageBox.critical(parent, "Binlex", message)


def show_info(message: str, parent=None) -> None:
    QMessageBox.information(parent, "Binlex", message)
