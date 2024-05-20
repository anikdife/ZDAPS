from PySide6.QtWidgets import QWidget, QApplication, QPushButton, QHBoxLayout
from PySide6.QtCore import Signal
import sys

class Emitter(QWidget):
    button_clicked = Signal(int)  # Define a signal with an integer parameter

    def __init__(self, parent=None):
        super().__init__(parent)
        self.button = QPushButton("hello", self)
        self.layout = QHBoxLayout(self)
        self.layout.addWidget(self.button)
        self.button.clicked.connect(self.emit_signal)

    def emit_signal(self):
        value = 42  # Example value to be passed as a parameter
        self.button_clicked.emit(value)  # Emit the signal with the parameter

class Receiver:
    def __init__(self):
        self.counter = 1

    def receive_signal(self, value):  # Define a slot that accepts the parameter
        print(f"Signal received with value: {value}")
        self.counter += value

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    emitter = Emitter()
    receiver = Receiver()

    # Connect the Emitter's signal to the Receiver's slot
    emitter.button_clicked.connect(receiver.receive_signal)

    emitter.show()
    sys.exit(app.exec())
