from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem

class AccuracyDialog(QDialog):
    def __init__(self, accuracy, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Accuracy")
        layout = QVBoxLayout()
        self.accuracy_label = QLabel(f"Accuracy: {accuracy}")
        self.accuracy_label.setStyleSheet(
            "background:pink"
        )
        layout.addWidget(self.accuracy_label)
        self.setLayout(layout)

class ConfusionMatrixDialog(QDialog):
    def __init__(self, confusion_matrix, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confusion Matrix")
        layout = QVBoxLayout()
        self.confusion_matrix_table = QTableWidget()
        self.confusion_matrix_table.setStyleSheet(
            "background:pink"
        )
        self.confusion_matrix_table.setRowCount(len(confusion_matrix))
        self.confusion_matrix_table.setColumnCount(len(confusion_matrix[0]))
        for i, row in enumerate(confusion_matrix):
            for j, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                self.confusion_matrix_table.setItem(i, j, item)
        layout.addWidget(self.confusion_matrix_table)
        self.setLayout(layout)

class ResultMatrixDialog(QDialog):
    def __init__(self, result_matrix, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Result Matrix")
        layout = QVBoxLayout()
        self.result_matrix_table = QTableWidget()
        self.result_matrix_table.setStyleSheet(
            "background:pink"
        )
        self.result_matrix_table.setRowCount(len(result_matrix))
        self.result_matrix_table.setColumnCount(len(result_matrix[0]))
        for i, row in enumerate(result_matrix):
            for j, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                self.result_matrix_table.setItem(i, j, item)
        layout.addWidget(self.result_matrix_table)
        self.setLayout(layout)
