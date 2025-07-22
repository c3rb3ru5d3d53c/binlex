# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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