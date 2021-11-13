import cutter

from PySide2.QtCore import QObject, SIGNAL
from PySide2.QtWidgets import QAction, QLabel

class MyDockWidget(cutter.CutterDockWidget):
    def __init__(self, parent, action):
        super(MyDockWidget, self).__init__(parent, action)
        self.setObjectName("MyDockWidget")
        self.setWindowTitle("My cool DockWidget")

        self._label = QLabel(self)
        self.setWidget(self._label)

        QObject.connect(cutter.core(), SIGNAL("seekChanged(RVA)"), self.update_contents)
        self.update_contents()

    def update_contents(self):
        disasm = cutter.cmd("pd 1").strip()

        instruction = cutter.cmdj("pdj 1")
        size = instruction[0]["size"]

        self._label.setText("Current disassembly:\n{}\nwith size {}".format(disasm, size))


class MyCutterPlugin(cutter.CutterPlugin):
    name = "My Plugin"
    description = "This plugin does awesome things!"
    version = "1.0"
    author = "1337 h4x0r"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        action = QAction("My Plugin", main)
        action.setCheckable(True)
        widget = MyDockWidget(main, action)
        main.addPluginDockWidget(widget, action)

    def terminate(self):
        pass

def create_cutter_plugin():
    return MyCutterPlugin()
