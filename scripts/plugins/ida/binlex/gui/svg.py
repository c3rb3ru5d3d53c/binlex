import json
from PyQt5.QtWidgets import QApplication, QWidget
from PyQt5.QtGui import QPainter, QColor, QWheelEvent, QMouseEvent, QTransform
from PyQt5.QtCore import Qt, QPointF, QRectF
import xml.etree.ElementTree as ET

class SVGWidget(QWidget):
    def __init__(self, svg_string: str, title: str = 'SVG Widget'):
        super().__init__()
        self.svg_string = svg_string
        self.title = title
        self.elements = []
        self.init_ui()
        self.parse_svg()

        self.scale_factor = 1.0
        self.min_scale = 0.1
        self.max_scale = 10.0
        self.last_mouse_pos = QPointF()
        self.dragging = False
        self.offset = QPointF(0, 0)

        self.current_hovered_element = None

    def init_ui(self):
        self.setWindowTitle(self.title)
        self.setMinimumSize(400, 400)
        self.resize(800, 600)
        self.setMouseTracking(True)

    def parse_svg(self):
        try:
            root = ET.fromstring(self.svg_string)
            namespace = ''
            if '}' in root.tag:
                namespace = root.tag.split('}')[0] + '}'

            for rect in root.findall('.//{}rect'.format(namespace)):
                x = float(rect.get('x', '0'))
                y = float(rect.get('y', '0'))
                width = float(rect.get('width', '0'))
                height = float(rect.get('height', '0'))
                fill = rect.get('fill', '#000000')
                data_info = rect.get('data-json', '{}')

                try:
                    metadata = json.loads(data_info)
                except:
                    metadata = {}

                color = QColor(fill)

                self.elements.append({
                    'x': x,
                    'y': y,
                    'width': width,
                    'height': height,
                    'color': color,
                    'metadata': metadata
                })
        except ET.ParseError as e:
            print(f"Error parsing SVG: {e}")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        transform = QTransform()
        transform.scale(self.scale_factor, self.scale_factor)
        transform.translate(self.offset.x(), self.offset.y())
        painter.setTransform(transform)

        for elem in self.elements:
            painter.setBrush(elem['color'])
            painter.setPen(Qt.NoPen)
            rect = QRectF(elem['x'], elem['y'], elem['width'], elem['height'])
            painter.drawRect(rect)

    def wheelEvent(self, event: QWheelEvent):
        zoom_in_factor = 1.15
        zoom_out_factor = 1 / zoom_in_factor

        if event.angleDelta().y() > 0:
            zoom_factor = zoom_in_factor
        else:
            zoom_factor = zoom_out_factor

        new_scale = self.scale_factor * zoom_factor
        if new_scale < self.min_scale or new_scale > self.max_scale:
            return

        mouse_pos = QPointF(event.pos())

        mouse_scene_pos = self.map_to_scene(mouse_pos)

        self.offset -= (zoom_factor - 1) * mouse_scene_pos

        self.scale_factor = new_scale

        self.update()

    def mousePressEvent(self, event: QMouseEvent):
        """
        Handles the mouse press event to initiate dragging or handle right-click.
        """
        if event.button() == Qt.LeftButton:
            self.dragging = True
            self.last_mouse_pos = QPointF(event.pos())
        elif event.button() == Qt.RightButton:
            scene_pos = self.map_to_scene(QPointF(event.pos()))
            rect = self.get_rect_at(scene_pos)
            if rect:
                # print metadata
                print(f"Metadata: {rect['metadata']}")

    def mouseMoveEvent(self, event: QMouseEvent):
        if self.dragging:
            current_mouse_pos = QPointF(event.pos())
            delta = current_mouse_pos - self.last_mouse_pos
            self.last_mouse_pos = current_mouse_pos
            self.offset += delta / self.scale_factor
            self.update()
        else:
            scene_pos = self.map_to_scene(QPointF(event.pos()))
            rect = self.get_rect_at(scene_pos)
            if rect != self.current_hovered_element:
                if rect and rect['metadata']:
                    tooltip_text = self.format_metadata(rect['metadata'])
                    self.setToolTip(tooltip_text)
                    self.current_hovered_element = rect
                else:
                    self.setToolTip('')
                    self.current_hovered_element = None

    def mouseReleaseEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.dragging = False

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.scale_factor = 1.0
            self.offset = QPointF(0, 0)
            self.update()

    def get_rect_at(self, pos: QPointF):
        for elem in reversed(self.elements):
            rect = QRectF(elem['x'], elem['y'], elem['width'], elem['height'])
            if rect.contains(pos):
                return elem
        return None

    def map_to_scene(self, pos: QPointF):
        x = (pos.x() - self.offset.x()) / self.scale_factor
        y = (pos.y() - self.offset.y()) / self.scale_factor
        return QPointF(x, y)

    def format_metadata(self, metadata: dict) -> str:
        if not metadata:
            return "No metadata available."
        lines = []
        for key, value in metadata.items():
            lines.append(f"{key}: {value}")
        return "\n".join(lines)