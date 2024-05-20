import sys
from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QPixmap, QImage, QPainter, QPainterPath, QMovie, QAction,QGradient, QColor
from PySide6.QtWidgets import QApplication, QWidget, QHBoxLayout,QVBoxLayout, QLabel, QPushButton, QMainWindow, QMenu, QSizePolicy
from tabulate import tabulate

class RectangularWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.result_selector = 2  # Set this value based on your logic
        self.label = QLabel("Rectangular Widget", self)
        self.label.setStyleSheet(
            "background:gray;"
            "border:0;"
            "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #CCAF50, stop:1 #FF8E3C);"
            "color: white;  /* Text color */"
            "font: bold;  /* Optional font styling */"
            "border-radius: 25;"
        )
        self.layout = QVBoxLayout(self)  # Use QHBoxLayout for horizontal arrangement
        self.layout.addWidget(self.label)
        self.setLayout(self.layout)
        self.setFixedSize(400, 400)  # Set your desired size
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground)  # Set transparent background
        self.setStyleSheet("background:transparent;border:0;")

        # Add a stop sniffing button
        self.stop_button = QPushButton("Stop Sniffing", self)
        self.stop_button.clicked.connect(self.stop_sniffing)
        # Set button size (adjust as needed)
        self.stop_button.setFixedSize(150, 50)
        # Apply the gradient to the button background
        self.stop_button.setStyleSheet(
            "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #CC2222, stop:1 #FF8E3C);"
            "color: white;  /* Text color */"
            "font: bold;  /* Optional font styling */"
            "border-radius: 25;"
        )
        self.layout.addWidget(self.stop_button)
        
        self.packet_capture = None

    def set_packet_capture(self, packet_capture):
        self.packet_capture = packet_capture
    def update_capture_info(self, http_count, https_count, icmp_count, counter):
        """ table = [["HTTP", "HTTPS", "ICMP", "Total"],
                [http_count, https_count, icmp_count, counter]]
        info_text = tabulate(table, headers="firstrow", tablefmt="pipe")
        self.label.setText(info_text) """
        
        info_text = "| {:^10} | {:^10} | {:^10} | {:^10} |\n".format("http", "https", "icmp", "Total")
        info_text += "-" * len(info_text) + "\n"
        info_text += "| {:^10} | {:^10} | {:^10} | {:^10} |".format(http_count, https_count, icmp_count, counter)
        self.label.setText(info_text)
    def stop_sniffing(self):
        print("stop sniffing called", self.packet_capture)
        if self.packet_capture:
            self.packet_capture.stop_sniffing()