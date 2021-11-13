import cutter

import os
from pathlib import Path
from functools import partial
from multiprocessing import Pool
from PySide2.QtCore import QObject, SIGNAL, Qt
from PySide2.QtWidgets import QAction, QVBoxLayout, QLabel, QWidget, QSizePolicy, QPushButton, QComboBox, QLineEdit, QFileDialog
from glob import glob

def load_traits_worker(file_path):

    """
    Binlex Trait Loader Thread
    """

    f = open(file_path, 'r')
    traits = {
        'name': Path(file_path).stem,
        'traits': list(set([line.strip() for line in f]))
    }
    f.close()
    return traits

class Binlex(cutter.CutterDockWidget):

    """
    Binlex Cutter Plugin
    """

    def __init__(self, parent, action):
        super(Binlex, self).__init__(parent, action)
        self.setObjectName("Binlex")
        self.setWindowTitle("Binlex")

        # Set Threads
        self.threads = 4

        content = QWidget()
        self.setWidget(content)

        # Create layout
        layout = QVBoxLayout(content)
        content.setLayout(layout)

        # Title Label
        label_title = QLabel(content)
        label_title_font = label_title.font()
        label_title_font.setPointSize(16)
        label_title_font.setBold(True)
        label_title.setText("Binlex - Genetic Binary Traits")
        label_title.setFont(label_title_font)
        layout.addWidget(label_title)
        layout.setAlignment(label_title, Qt.AlignHCenter | Qt.AlignTop)

        # Load Traits Button
        btn_load = QPushButton(content)
        btn_load.setText("Load Traits")
        layout.addWidget(btn_load)
        layout.setAlignment(btn_load, Qt.AlignRight | Qt.AlignBottom)
        QObject.connect(btn_load, SIGNAL("clicked()"), self.load_traits)

        self.show()

    def load_traits(self):
        directory = folderpath = QFileDialog.getExistingDirectory(self, 'Select Folder')
        cutter.message("[-] binlex loading traits...")
        files = glob('{directory}**/*.traits'.format(directory=directory), recursive=True)
        files = [f for f in files if os.path.isfile(f)]
        if len(files) <= 0:
            cutter.message("[x] no binlex traits files found!")
            return None
        pool = Pool(processes=self.threads)
        results = pool.map(partial(load_traits_worker,), files)
        cutter.message(str(results))
        cutter.message("[*] binlex finished loading traits")

class BinlexPlugin(cutter.CutterPlugin):

    """
    Binlex Plugin Class
    """

    name        = "Binlex"
    description = "Binary Genetic Traits Plugin"
    version     = "1.0.0"
    author      = "@c3rb3ru5d3d53c"

    def __init__(self):
        super(BinlexPlugin, self).__init__()

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        action = QAction("Binlex", main)
        action.setCheckable(True)
        widget = Binlex(main, action)
        main.addPluginDockWidget(widget, action)

    def terminate(self):
        cutter.message("[*] binlex plugin shutting down...")

def create_cutter_plugin():
    return BinlexPlugin()
