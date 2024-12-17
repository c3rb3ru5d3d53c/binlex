
import zlib
import base64
from assets import LOGO
from styles import QPUSHBUTTON_STYLE
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QPushButton
from PyQt5.QtCore import Qt, QRect
from PyQt5.QtGui import QPixmap, QPainter

class Main(QDialog):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
        self.pixmap = QPixmap()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Binlex')
        self.setFixedSize(300, 200)
        self.setWindowFlags(Qt.WindowFlags(Qt.Dialog | Qt.ApplicationModal))

        image_data = zlib.decompress(base64.b64decode(LOGO))
        self.pixmap.loadFromData(image_data)

        layout = QVBoxLayout()

        btn1 = QPushButton('Export')
        btn1.clicked.connect(self.plugin.export)

        btn1.setStyleSheet(QPUSHBUTTON_STYLE)

        layout.addWidget(btn1)

        btn3 = QPushButton('Function Table')
        btn3.clicked.connect(self.plugin.open_table_window)

        btn3.setStyleSheet(QPUSHBUTTON_STYLE)

        layout.addWidget(btn3)

        btn2 = QPushButton('About')
        btn2.clicked.connect(self.plugin.open_about_window)

        btn2.setStyleSheet(QPUSHBUTTON_STYLE)

        layout.addWidget(btn2)

        self.setLayout(layout)

    def paintEvent(self, event):
        super().paintEvent(event)

        if self.pixmap.isNull():
            return

        painter = QPainter(self)

        widget_width = self.width()
        widget_height = self.height()

        pixmap_width = self.pixmap.width()
        pixmap_height = self.pixmap.height()

        scale_x = widget_width / pixmap_width
        scale_y = widget_height / pixmap_height
        scale = min(scale_x, scale_y)

        new_width = int(pixmap_width * scale)
        new_height = int(pixmap_height * scale)

        x_offset = (widget_width - new_width) // 2
        y_offset = (widget_height - new_height) // 2

        target_rect = QRect(x_offset, y_offset, new_width, new_height)
        painter.drawPixmap(target_rect, self.pixmap, self.pixmap.rect())