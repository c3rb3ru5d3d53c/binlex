import sys
import jq
from PyQt5.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QWidget, QLabel,
    QLineEdit, QPushButton, QTextEdit, QMessageBox,
    QMenu, QAction, QFileDialog
)
import ida_kernwin

class JSONSearchWindow(ida_kernwin.PluginForm):
    def __init__(self, json_objects: list[dict]):
        super().__init__()
        self.json_objects = json_objects

    def OnCreate(self, form):
        # Get a parent widget for the dockable window
        self.parent = self.FormToPyQtWidget(form)

        # Main layout
        main_layout = QVBoxLayout()

        # Query bar layout
        query_layout = QHBoxLayout()
        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("Enter jq query here...")
        query_button = QPushButton("Query")
        query_button.clicked.connect(self.perform_query)

        query_layout.addWidget(QLabel("JQ Query:"))
        query_layout.addWidget(self.query_input)
        query_layout.addWidget(query_button)

        # Results text box
        self.results_box = ResultsTextEdit()
        self.results_box.setReadOnly(True)

        # Add widgets to the main layout
        main_layout.addLayout(query_layout)
        main_layout.addWidget(self.results_box)

        # Set the layout to the parent widget
        container = QWidget()
        container.setLayout(main_layout)
        layout = QVBoxLayout()
        layout.addWidget(container)
        self.parent.setLayout(layout)

    def OnClose(self, form):
        # Perform any cleanup if necessary
        pass

    def perform_query(self):
        query = self.query_input.text()
        try:
            # Combine all JSON objects into a list

            # Apply jq query
            result = jq.compile(query).input(self.json_objects).all()

            # Display results
            self.results_box.setPlainText(str(result))
        except Exception as e:
            QMessageBox.critical(self.parent, "Query Error", f"An error occurred: {e}")

class ResultsTextEdit(QTextEdit):
    def contextMenuEvent(self, event):
        # Create a custom context menu
        menu = QMenu(self)

        # Add a save action
        save_action = QAction("Save", self)
        save_action.triggered.connect(self.save_to_file)
        menu.addAction(save_action)

        # Add other default actions from the standard context menu
        standard_menu = self.createStandardContextMenu()
        for action in standard_menu.actions():
            menu.addAction(action)

        # Show the context menu
        menu.exec_(event.globalPos())


    def save_to_file(self):
        # Open a file dialog to select a save location
        file_path = ida_kernwin.ask_file(1, "*.json", 'Export Binlex JQ Query Results')
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(self.toPlainText())
                print("[*] results saved successfully")
            except Exception as e:
                print(f"[x] {e}")
