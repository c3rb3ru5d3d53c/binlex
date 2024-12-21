from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QProgressBar, QWidget

class Progress(QMainWindow):
    def __init__(self, title='Progress', max_value=100):
        super().__init__()

        self.is_closed = False

        self.setWindowTitle(title)
        self.setGeometry(100, 100, 300, 100)

        self.central_widget = QWidget()
        self.layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(max_value)
        self.layout.addWidget(self.progress_bar)

        self.central_widget.setLayout(self.layout)
        self.setCentralWidget(self.central_widget)

    def set(self, value: int):
        self.progress_bar.setValue(value)
        QApplication.processEvents()

    def increment(self, value: int = 1):
        """Increment the progress bar by the specified value."""
        current_value = self.progress_bar.value()
        new_value = min(self.progress_bar.maximum(), current_value + value)
        self.progress_bar.setValue(new_value)
        QApplication.processEvents()

    def closeEvent(self, event):
        """Handle the window close event."""
        self.is_closed = True
        event.accept()