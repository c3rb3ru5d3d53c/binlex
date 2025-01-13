from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QDialogButtonBox, QHBoxLayout, QLabel, QSpacerItem, QSizePolicy
)

class OkayCancelDialog(QDialog):
    def __init__(self, title: str = 'Select an Option', okay_text="OK", cancel_text="Cancel", width=300, height=50, parent=None):
        super().__init__(parent)

        # Set dialog properties
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(width, height)

        # Main layout
        main_layout = QVBoxLayout(self)

        # Add vertical spacer for alignment
        main_layout.addSpacerItem(QSpacerItem(0, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Button box with OK and Cancel buttons
        self.button_box = QDialogButtonBox()
        self.ok_button = self.button_box.addButton(okay_text, QDialogButtonBox.AcceptRole)
        self.cancel_button = self.button_box.addButton(cancel_text, QDialogButtonBox.RejectRole)

        # Connect button signals
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        # Horizontal layout for centering buttons
        button_layout = QHBoxLayout()
        button_layout.addSpacerItem(QSpacerItem(20, 0, QSizePolicy.Expanding, QSizePolicy.Minimum))
        button_layout.addWidget(self.button_box)
        button_layout.addSpacerItem(QSpacerItem(20, 0, QSizePolicy.Expanding, QSizePolicy.Minimum))

        # Add button layout to main layout
        main_layout.addLayout(button_layout)

        # Add another vertical spacer for alignment
        main_layout.addSpacerItem(QSpacerItem(0, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Set the final layout
        self.setLayout(main_layout)
