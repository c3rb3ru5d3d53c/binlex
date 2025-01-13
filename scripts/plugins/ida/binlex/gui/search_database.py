from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QLabel,
    QDialog,
    QVBoxLayout,
    QLineEdit,
    QComboBox,
    QDoubleSpinBox,
    QSpinBox,
    QDialogButtonBox,
    QHBoxLayout,
    QPushButton,
    QCheckBox,
)
from lib import IDA
from lib import BLClient

class SearchDatabaseDialog(QDialog):
    def __init__(self, databases: list = ['default', 'goodware', 'malware'], parent=None):
        super(SearchDatabaseDialog, self).__init__(parent)
        self.setWindowTitle('Binlex Database Search Options')
        self.setModal(True)

        self.setFixedWidth(500)

        layout = QVBoxLayout(self)

        url = IDA().get_registry_value('url')
        api_key = IDA().get_registry_value('api_key')

        try:
            if url is not None and api_key is not None:
                client = BLClient(url=url, api_key=api_key)
                status, response = client.databases()
                if status == 200: databases = response
        except:
            pass

        self.url_label = QLabel('Server URL')
        self.url_input = QLineEdit()
        if url is not None: self.url_input.setText(url)
        layout.addWidget(self.url_label)
        layout.addWidget(self.url_input)

        self.api_key_label = QLabel('API Key')
        api_key_layout = QHBoxLayout()
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        if api_key is not None: self.api_key_input.setText(api_key)
        api_key_layout.addWidget(self.api_key_input)

        self.api_key_toggle_button = QPushButton('Show')
        self.api_key_toggle_button.setCheckable(True)
        self.api_key_toggle_button.clicked.connect(self.toggle_api_key_visibility)
        api_key_layout.addWidget(self.api_key_toggle_button)

        layout.addWidget(self.api_key_label)
        layout.addLayout(api_key_layout)

        self.database_label = QLabel('Database')
        self.database_input = QComboBox()
        self.database_input.addItems(databases)
        self.database_input.setCurrentText('default')
        layout.addWidget(self.database_label)
        layout.addWidget(self.database_input)

        self.minhash_score_threshold_label = QLabel('MinHash Score Threshold')
        self.minhash_score_threshold = QDoubleSpinBox()
        self.minhash_score_threshold.setRange(0.0, 1.0)
        self.minhash_score_threshold.setSingleStep(0.01)
        self.minhash_score_threshold.setValue(0.75)
        layout.addWidget(self.minhash_score_threshold_label)
        layout.addWidget(self.minhash_score_threshold)

        self.mininum_size_label = QLabel('Mininum Size Threshold')
        self.mininum_size = QSpinBox()
        self.mininum_size.setRange(32, 2048)
        layout.addWidget(self.mininum_size_label)
        layout.addWidget(self.mininum_size)

        self.size_ratio_label = QLabel('Size Ratio Threshold')
        self.size_ratio = QDoubleSpinBox()
        self.size_ratio.setRange(0.0, 1.0)
        self.size_ratio.setSingleStep(0.01)
        self.size_ratio.setValue(0.75)
        layout.addWidget(self.size_ratio_label)
        layout.addWidget(self.size_ratio)

        self.chromosome_minhash_ratio_threshold_label = QLabel('Chromosome MinHash Ratio Threshold')
        self.chromosome_minhash_ratio_threshold = QDoubleSpinBox()
        self.chromosome_minhash_ratio_threshold.setRange(0.0, 1.0)
        self.chromosome_minhash_ratio_threshold.setSingleStep(0.01)
        self.chromosome_minhash_ratio_threshold.setValue(0.75)
        layout.addWidget(self.chromosome_minhash_ratio_threshold_label)
        layout.addWidget(self.chromosome_minhash_ratio_threshold)

        self.combined_ratio_threshold_label = QLabel('Combined Ratio Threshold')
        self.combined_ratio_threshold_input = QDoubleSpinBox()
        self.combined_ratio_threshold_input.setRange(0.0, 1.0)
        self.combined_ratio_threshold_input.setSingleStep(0.01)
        self.combined_ratio_threshold_input.setValue(0.75)
        layout.addWidget(self.combined_ratio_threshold_label)
        layout.addWidget(self.combined_ratio_threshold_input)

        self.gnn_similarity_threshold_label = QLabel('GNN Similarity Threshold')
        self.gnn_similarity_threshold_input = QDoubleSpinBox()
        self.gnn_similarity_threshold_input.setRange(0.0, 1.0)
        self.gnn_similarity_threshold_input.setSingleStep(0.01)
        self.gnn_similarity_threshold_input.setValue(0.75)
        layout.addWidget(self.gnn_similarity_threshold_label)
        layout.addWidget(self.gnn_similarity_threshold_input)

        self.limit_label = QLabel('Limit (Function Top-K)')
        self.limit_input = QSpinBox()
        self.limit_input.setRange(1, 32)
        self.limit_input.setValue(3)
        layout.addWidget(self.limit_label)
        layout.addWidget(self.limit_input)

        self.exclude_named_functions = QCheckBox('Exclude LHS Named Functions')
        self.exclude_named_functions.setChecked(True)
        layout.addWidget(self.exclude_named_functions)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def toggle_api_key_visibility(self):
        if self.api_key_toggle_button.isChecked():
            self.api_key_input.setEchoMode(QLineEdit.Normal)
            self.api_key_toggle_button.setText('Hide')
        else:
            self.api_key_input.setEchoMode(QLineEdit.Password)
            self.api_key_toggle_button.setText('Show')

    def get_inputs(self):
        return (
            self.minhash_score_threshold.value(),
            self.mininum_size.value(),
            self.size_ratio.value(),
            self.chromosome_minhash_ratio_threshold.value(),
            self.combined_ratio_threshold_input.value(),
            self.gnn_similarity_threshold_input.value(),
            self.url_input.text(),
            self.api_key_input.text(),
            self.database_input.currentText(),
            self.limit_input.value(),
            self.exclude_named_functions.isChecked(),
        )
