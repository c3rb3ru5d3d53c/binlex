import cutter
import re
import os
import tempfile
import subprocess
from pathlib import Path
from functools import partial
from multiprocessing import Pool
from PySide2.QtCore import QObject, SIGNAL, Qt
from PySide2.QtWidgets import *
from glob import glob

def load_traits_worker(file_path):

    """
    Binlex Load Traits Thread
    """

    f = open(file_path, 'r')
    traits = list(set([line.strip() for line in f]))
    f.close()
    data = []
    for trait in traits:
        data.append(
            {
                'name': Path(file_path).stem,
                'trait': trait
            }
        )
    return data

def scan_traits_workder(trait):

    """
    Binlex Scan Trait
    """

    pass

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

        menu = QWidget(content)
        menu_layout = QHBoxLayout(menu)

        traits_library_btn = QPushButton(menu)
        traits_library_btn.setText('Traits Library')
        QObject.connect(traits_library_btn, SIGNAL("clicked()"), self.traits_library)

        matches_btn = QPushButton(menu)
        matches_btn.setText('Matches')
        QObject.connect(matches_btn, SIGNAL("clicked()"), self.matches)

        similarities_btn = QPushButton(menu)
        similarities_btn.setText('Similarities')
        QObject.connect(similarities_btn, SIGNAL("clicked()"), self.similarities)
        
        menu_layout.addWidget(traits_library_btn)
        menu_layout.addWidget(matches_btn)
        menu_layout.addWidget(similarities_btn)
        menu.setLayout(menu_layout)

        layout.addWidget(menu)

        # Traits Table
        self.table_traits = QTableWidget()
        self.table_traits.setShowGrid(False)
        self.table_traits.verticalHeader().hide()
        self.table_traits.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_traits.setColumnCount(2)
        self.table_traits.setRowCount(1)
        self.table_traits.setHorizontalHeaderLabels(['Name', 'Trait'])
        self.table_traits.setSortingEnabled(True)
        self.table_traits.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table_traits.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table_traits.setContentsMargins(0,0,0,0)
        self.table_traits.setEditTriggers(QAbstractItemView.NoEditTriggers)

        header = self.table_traits.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        self.table_traits.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
        self.table_traits.setAlternatingRowColors(True)
        self.table_traits.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) 


        layout.addWidget(self.table_traits)
        layout.setAlignment(self.table_traits, Qt.AlignLeft)

        # Search Type
        search_type = QComboBox()
        search_type.addItems(["Name", "Trait"])
        layout.addWidget(search_type)
        layout.setAlignment(search_type, Qt.AlignRight | Qt.AlignBottom)

        # Search Traits
        search_traits = QLineEdit()
        search_traits.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        search_traits.setContentsMargins(0,0,0,0)
        search_traits.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
        search_traits.setPlaceholderText("Quick Filter")
        layout.addWidget(search_traits)

        # Load Traits Button
        btn_load = QPushButton(content)
        btn_load.setText("Load Traits")
        layout.addWidget(btn_load)
        layout.setAlignment(btn_load, Qt.AlignRight | Qt.AlignBottom)
        QObject.connect(btn_load, SIGNAL("clicked()"), self.load_traits)

        self.show()

    def generate_yara_rule(self, traits):
        cutter.message('[-] binlex generating yara signature...')
        yara_rule = 'rule binlex {\n\tstrings:\n'
        for i in range(0, len(traits)):
            yara_rule = yara_rule + '\t\t${i} = {open}{trait}{closed}\n'.format(i=i,trait=traits[i]['trait'],open='{',closed='}')
        yara_rule = yara_rule + '\n\tcondition:\n\t\tany of them\n}'
        cutter.message('[*] binlex yara generation complete')
        return yara_rule


    def yara_scan(self, rule, file_path):
        cutter.message('[-] binlex starting yara scan...')
        yara_rule_file = tempfile.NamedTemporaryFile()
        yara_rule_file.write(str.encode(yara_rule))
        command = 'yara -w -s {rule} {file_path}'.format(rule=yara_rule_file.name,file_path=file_path)
        out = subprocess.getoutput(command)
        yara_rule_file.close()
        cutter.message('[*] binlex yara scan complete')
        return out

    def load_traits(self):
        directory = QFileDialog.getExistingDirectory(self, 'Select Folder')
        cutter.message("[-] binlex loading traits...")
        files = glob('{directory}**/*.traits'.format(directory=directory), recursive=True)
        files = [f for f in files if os.path.isfile(f)]
        if len(files) <= 0:
            cutter.message("[x] no binlex traits files found!")
            return None
        pool = Pool(processes=self.threads)
        traits = pool.map(partial(load_traits_worker,), files)
        traits = [item for sublist in traits for item in sublist]
        yara_rule = self.generate_yara_rule(traits)
        self.yara_scan(yara_rule, '/usr/bin/ls')
        self.table_traits.setRowCount(len(traits))
        for i in range(0, len(traits)):
            self.table_traits.setItem(i, 0, QTableWidgetItem(traits[i]['name']))
            self.table_traits.setItem(i, 1, QTableWidgetItem(traits[i]['trait']))
        self.table_traits.resizeColumnsToContents()
        self.table_traits.resizeRowsToContents()  
        self.show()
        cutter.message("[*] binlex finished loading traits")
    
    def traits_library():
        pass

    def matches():
        pass

    def similarities():
        pass


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
