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

import json
from PyQt5.QtWidgets import QApplication, QWidget
from PyQt5.QtGui import QPainter, QColor, QWheelEvent, QMouseEvent, QTransform
from PyQt5.QtCore import Qt, QPointF, QRectF
import xml.etree.ElementTree as ET
import idc
import ida_kernwin

class SVGWidget(QWidget):
    def __init__(self, svg_string: str, title: str = 'SVG Widget'):
        super().__init__()
        self.svg_string = svg_string
        self.title = title
        self.elements = []
        self.svg_width = 800  # Default width
        self.svg_height = 600  # Default height
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
        self.setMinimumSize(400, 400)  # Ensure minimum size
        self.resize(600, 400)  # Set initial modest size
        self.setMouseTracking(True)

    def parse_svg(self):
        try:
            root = ET.fromstring(self.svg_string)
            namespace = ''
            if '}' in root.tag:
                namespace = root.tag.split('}')[0] + '}'

            # Get SVG dimensions and ensure they're integers
            self.svg_width = int(float(root.get('width', '800')))
            self.svg_height = int(float(root.get('height', '600')))

            # Ensure dimensions don't exceed a predefined maximum
            max_width, max_height = 800, 600  # Example maximum sizes
            self.svg_width = min(self.svg_width, max_width)
            self.svg_height = min(self.svg_height, max_height)

            # Optionally, resize only if the dimensions are smaller than the initial size
            if self.svg_width <= 600 and self.svg_height <= 400:
                self.resize(self.svg_width, self.svg_height)

            for rect in root.findall('.//{}rect'.format(namespace)):
                x = float(rect.get('x', '0'))
                y = float(rect.get('y', '0'))
                width = float(rect.get('width', '0'))
                height = float(rect.get('height', '0'))
                fill = rect.get('fill', '#000000')  # Default to black
                address = rect.get('address', None)

                # Handle `rgb(r,g,b)` syntax
                if fill.startswith("rgb("):
                    try:
                        rgb_values = fill[4:-1].split(",")
                        r, g, b = map(int, rgb_values)
                        color = QColor(r, g, b)
                    except ValueError:
                        color = QColor("#000000")  # Default to black if parsing fails
                else:
                    color = QColor(fill)  # Assume hex color if not `rgb`

                self.elements.append({
                    'x': x,
                    'y': y,
                    'width': width,
                    'height': height,
                    'color': color,
                    'address': address
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

        # Determine zoom factor based on scroll direction
        if event.angleDelta().y() > 0:
            zoom_factor = zoom_in_factor
        else:
            zoom_factor = zoom_out_factor

        # Compute the new scale factor
        new_scale = self.scale_factor * zoom_factor
        if new_scale < self.min_scale or new_scale > self.max_scale:
            return

        # Calculate the center point of the widget in scene coordinates
        center_widget = QPointF(self.width() / 2, self.height() / 2)
        center_scene = self.map_to_scene(center_widget)

        # Update the offset to maintain the center
        self.offset -= (center_scene * (zoom_factor - 1))

        # Apply the new scale
        self.scale_factor = new_scale

        # Trigger a redraw
        self.update()


    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.dragging = True
            self.last_mouse_pos = QPointF(event.pos())
        elif event.button() == Qt.RightButton:
            scene_pos = self.map_to_scene(QPointF(event.pos()))
            rect = self.get_rect_at(scene_pos)
            if rect:
                address = rect.get('address')
                if address:
                    try:
                        ida_kernwin.jumpto(int(address), ida_kernwin.UIJMP_DONTPUSH)
                    except ValueError:
                        print(f"Invalid address: {address}")

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
                if rect and rect['address']:
                    tooltip_text = f"Address: {hex(int(rect['address']))}"
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
