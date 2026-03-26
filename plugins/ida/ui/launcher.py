from __future__ import annotations

try:
    from qt_compat import exec_dialog, import_qt
except ModuleNotFoundError:  # pragma: no cover - fallback for packaged package layouts
    from ..qt_compat import exec_dialog, import_qt


def _fuzzy_score(query: str, label: str) -> tuple[int, int] | None:
    if not query:
        return (0, len(label))

    text = label.lower()
    parts = [part for part in query.lower().split() if part]
    if not parts:
        return (0, len(label))

    total_penalty = 0
    total_span = 0
    for part in parts:
        score = _subsequence_score(part, text)
        if score is None:
            return None
        total_penalty += score[0]
        total_span += score[1]
    return (total_penalty, total_span)


def _subsequence_score(query: str, text: str) -> tuple[int, int] | None:
    start = -1
    position = 0
    gap_penalty = 0

    for char in query:
        index = text.find(char, position)
        if index < 0:
            return None
        if start < 0:
            start = index
        gap_penalty += index - position
        position = index + 1

    span = position - start
    return (gap_penalty + start, span)


def open_launcher(commands: list[tuple[str, object]]) -> None:
    _, QtCore, _, QtWidgets = import_qt()

    class LauncherDialog(QtWidgets.QDialog):
        def __init__(self) -> None:
            super().__init__(None)
            self.commands = commands
            self.filtered: list[tuple[str, object]] = []
            self.setWindowTitle("Binlex")
            self.resize(620, 360)

            layout = QtWidgets.QVBoxLayout(self)

            self.search = QtWidgets.QLineEdit(self)
            self.search.setPlaceholderText("Type a Binlex command")
            layout.addWidget(self.search)

            self.listing = QtWidgets.QListWidget(self)
            self.listing.setUniformItemSizes(True)
            self.listing.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
            layout.addWidget(self.listing)

            self.search.textChanged.connect(self._refresh)
            self.search.returnPressed.connect(self._execute_current)
            self.listing.itemActivated.connect(lambda _item: self._execute_current())

            self.search.setFocus(QtCore.Qt.OtherFocusReason)
            self._refresh()

        def _refresh(self) -> None:
            query = self.search.text().strip()
            ranked: list[tuple[tuple[int, int], str, object]] = []
            for label, callback in self.commands:
                score = _fuzzy_score(query, label)
                if score is None:
                    continue
                ranked.append((score, label, callback))
            ranked.sort(key=lambda item: (item[0][0], item[0][1], item[1]))

            self.filtered = [(label, callback) for _, label, callback in ranked]
            self.listing.clear()
            for label, _ in self.filtered:
                self.listing.addItem(label)
            if self.filtered:
                self.listing.setCurrentRow(0)

        def _execute_current(self) -> None:
            row = self.listing.currentRow()
            if row < 0 or row >= len(self.filtered):
                return
            _, callback = self.filtered[row]
            callback()
            self.accept()

    dialog = LauncherDialog()
    exec_dialog(dialog)
