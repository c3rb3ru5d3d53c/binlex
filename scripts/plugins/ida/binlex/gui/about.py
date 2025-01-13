from lib.assets import LOGO
from lib.assets import MOVIE
from lib.text import CREDITS

import zlib
import base64
from PyQt5.QtCore import Qt, QBuffer, QTimer, QByteArray
from PyQt5.QtGui import QMovie
from PyQt5.QtWidgets import QLabel, QDialog

class About(QDialog):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
        self.gif_data = zlib.decompress(base64.b64decode(MOVIE))
        self.gif_buffer = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('About')
        self.setFixedSize(300, 200)
        self.setWindowFlags(Qt.WindowFlags(Qt.Dialog | Qt.ApplicationModal))

        self.gif_label = QLabel(self)
        self.gif_label.setGeometry(0, 0, 300, 200)
        self.gif_buffer = QBuffer()
        self.gif_buffer.setData(QByteArray(self.gif_data))
        self.gif_buffer.open(QBuffer.ReadOnly)

        movie = QMovie(self.gif_buffer, b'gif')
        self.gif_label.setMovie(movie)
        movie.start()

        self.overlay_label = QLabel(self)
        self.overlay_label.setGeometry(0, 0, 300, 200)
        self.overlay_label.setStyleSheet("background-color: rgba(0, 0, 0, 150);")
        self.overlay_label.setAttribute(Qt.WA_TransparentForMouseEvents)

        self.text_label = QLabel(self)
        self.text_label.setGeometry(0, 200, 300, 200)
        self.text_label.setText(CREDITS)
        self.text_label.setAlignment(Qt.AlignCenter)
        self.text_label.setStyleSheet(
            "color: white; font-size: 14px; background: transparent; font-weight: bold;"
        )

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.scroll_text)
        self.timer.start(40)

        self.text_y_pos = 200

    def scroll_text(self):
        self.text_y_pos -= 1
        if self.text_y_pos + self.text_label.height() < 0:
            self.text_y_pos = self.height()

        self.text_label.move(0, self.text_y_pos)
