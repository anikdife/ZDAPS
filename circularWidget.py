import sys
from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QPixmap, QImage, QPainter, QPainterPath, QMovie, QAction
from PySide6.QtWidgets import QApplication, QWidget, QHBoxLayout, QLabel, QPushButton, QMainWindow, QMenu, QSizePolicy
from packetCapture import PacketCapture

class CircularImageWidget(QWidget):
    jpegClicked = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.circular_selector = 1  # Set this value based on your logic
        self.image_label = QLabel(self)
        self.layout = QHBoxLayout(self)  # Use QHBoxLayout for horizontal arrangement
        self.layout.addWidget(self.image_label)
        self.setLayout(self.layout)
        self.setFixedSize(400, 400)  # Set your desired size
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground)  # Set transparent background
        self.image_label.mousePressEvent = self.on_mouse_press_event
        self.packet_capture=PacketCapture()
        self.update_image()
        self.packet_capture = None

    def set_packet_capture(self, packet_capture):
        self.packet_capture = packet_capture

    def on_mouse_press_event(self, event):
        if event.button() == Qt.LeftButton:
            self.circular_selector = 2
            self.update_image()
            self.start_capture()
            self.jpegClicked.emit(2,0)  # Emit signal when JPEG is clicked

    def get_circular_selector_value(self, value):
        print("received:", value)
    def receive_stop_sniff(self):
        print("sniff stop in circular widget")
        self.circular_selector=1
        self.update_image()

    def toggle_capture(self):
        if self.circular_selector == 2:
            self.circular_selector = 1
        else:
            self.circular_selector = 2
        self.update_image()

    def update_image(self):
        if self.circular_selector == 1:
            image_path = "design5.jpeg"  # Replace with your image path
            image = QImage(image_path)
            pixmap = QPixmap.fromImage(image)
            pixmap = pixmap.scaled(self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            pixmap = self.circular_pixmap(pixmap)  # Apply circular clipping to the pixmap
            self.image_label.setPixmap(pixmap)
            self.image_label.setStyleSheet("background-color: transparent;border:0;")  # Set transparent background for QLabel
        else:
            gif_path = "R.gif"  # Replace with your gif path
            movie = QMovie(gif_path)
            movie.setScaledSize(self.size())  # Set the size of the movie to match the widget
            self.image_label.setMovie(movie)
            movie.start()
            self.image_label.setAutoFillBackground(False)  # Ensure QLabel doesn't fill its background
            self.image_label.setStyleSheet("background-color: transparent;")  # Set transparent background for QLabel
            self.maskPixmap = self.generateMaskPixmap(movie.currentPixmap())
            self.setMask(self.maskPixmap.mask())

    """ def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.circular_selector = 2
            self.update_image() 

        def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setCompositionMode(QPainter.CompositionMode_Clear)
        painter.fillRect(self.rect(), Qt.transparent)
        painter.setCompositionMode(QPainter.CompositionMode_SourceOver)

        if self.circular_selector == 1:
            image_path = "design5.jpeg"  # Replace with your image path
            image = QImage(image_path)
            pixmap = QPixmap.fromImage(image)
            pixmap = pixmap.scaled(self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)

            # Create a circular shape using QPainterPath
            path = QPainterPath()
            path.addEllipse(self.rect())
            painter.setClipPath(path)

            painter.drawPixmap(0, 0, pixmap) """

    def circular_pixmap(self, pixmap):
        """
        Apply circular clipping to the pixmap.
        """
        size = min(pixmap.width(), pixmap.height())
        circular_pixmap = QPixmap(pixmap.size())
        circular_pixmap.fill(Qt.transparent)
        painter = QPainter(circular_pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(Qt.black)
        painter.drawEllipse(0, 0, size, size)
        painter.end()
        pixmap.setMask(circular_pixmap.mask())
        return pixmap
    def generateMaskPixmap(self, pixmap):
        mask = pixmap.createMaskFromColor(Qt.transparent)
        masked_pixmap = pixmap.copy(mask.rect())
        return masked_pixmap
    def startPacketCapture(self):
        packet_capture = PacketCapture()  # Start packet capture
    def start_capture(self):
        if self.circular_selector == 2:
            self.packet_capture.start_sniffing()