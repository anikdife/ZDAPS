import sys
from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QPixmap, QImage, QPainter, QPainterPath, QMovie, QAction
from PySide6.QtWidgets import QApplication, QWidget, QHBoxLayout, QLabel, QPushButton, QMainWindow, QMenu, QSizePolicy

class CircularImageWidget(QWidget):
    def __init__(self, second_widget, parent=None):
        super().__init__(parent)
        self.circular_selector = 1  # Set this value based on your logic
        self.image_label = QLabel(self)
        self.close_button = QPushButton("Stop C", self)
        self.close_button.setStyleSheet("position: absolute; top:0; right: 0; padding:2px;border-radius:5px;background:#DD2222;color:#f0f0f0;")
        self.close_button.clicked.connect(self.toggle_capture)  # Close button action
        self.close_button.hide()  # Initially hide the button
        self.layout = QHBoxLayout(self)  # Use QHBoxLayout for horizontal arrangement
        self.layout.addWidget(self.image_label)
        self.layout.addWidget(self.close_button)
        self.setLayout(self.layout)
        self.setFixedSize(400, 400)  # Set your desired size
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground)  # Set transparent background
        self.second_widget = second_widget
        # Set size policy for the button
        self.close_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        # Set minimum and maximum sizes for the button
        self.close_button.setMinimumSize(self.close_button.sizeHint())
        self.close_button.setMaximumSize(self.close_button.sizeHint())
    def get_circular_selector_value(self, value):
        print("received:", value)
    def toggle_capture(self):
        if self.circular_selector == 2:
            self.circular_selector = 1
        else:
            self.circular_selector = 2
        self.update_image()

    def update_image(self):
        if self.circular_selector == 1:
            image_path = "design2.jpeg"  # Replace with your image path
            image = QImage(image_path)
            pixmap = QPixmap.fromImage(image)
            pixmap = pixmap.scaled(self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            pixmap = self.circular_pixmap(pixmap)  # Apply circular clipping to the pixmap
            self.image_label.setPixmap(pixmap)
            self.image_label.setStyleSheet("background-color: transparent;border:0;")  # Set transparent background for QLabel
            self.close_button.hide()  # Hide the button when showing the image
        else:
            gif_path = "R.gif"  # Replace with your gif path
            movie = QMovie(gif_path)
            movie.setScaledSize(self.size())  # Set the size of the movie to match the widget
            self.image_label.setMovie(movie)
            movie.start()
            self.image_label.setAutoFillBackground(False)  # Ensure QLabel doesn't fill its background
            self.image_label.setStyleSheet("background-color: transparent;")  # Set transparent background for QLabel
            self.close_button.show()  # Show the button when showing the GIF
            # Show the second widget with red background
            self.second_widget.setStyleSheet("background-color: #888;border:0;")

    def mousePressEvent(self, event):
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
            image_path = "design2.jpeg"  # Replace with your image path
            image = QImage(image_path)
            pixmap = QPixmap.fromImage(image)
            pixmap = pixmap.scaled(self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)

            # Create a circular shape using QPainterPath
            path = QPainterPath()
            path.addEllipse(self.rect())
            painter.setClipPath(path)

            painter.drawPixmap(0, 0, pixmap)

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

class RectangularWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.result_selector = 2  # Set this value based on your logic
        self.label = QLabel("Rectangular Widget", self)
        self.label.setStyleSheet("background:transparent;border:0;")
        self.layout = QHBoxLayout(self)  # Use QHBoxLayout for horizontal arrangement
        self.layout.addWidget(self.label)
        self.setLayout(self.layout)
        self.setFixedSize(400, 400)  # Set your desired size
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground)  # Set transparent background
        self.setStyleSheet("background:transparent;border:0;")
class MainWindow(QMainWindow):
    stopCaptureSignal=Signal(int)
    def __init__(self):
        super().__init__()
        w = 400
        h = 400
        self.resize(w, h)
        self.circular_selector = 1

        # Remove frame and make the window transparent
        self.setWindowFlag(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        # Create instances of CircularImageWidget and RectangularWidget
        self.rectangular_widget = RectangularWidget(self)
        self.circular_widget = CircularImageWidget(self)

        # Set the layout for the main window
        main_layout = QHBoxLayout()
        main_layout.addWidget(self.circular_widget)
        main_layout.addWidget(self.rectangular_widget)

        # Create and set central widget
        central_widget = QWidget(self)
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Create dropdown menu button
        self.menu = QMenu()
        self.action1 = QAction("Action 1", self)
        self.action2 = QAction("Action 2", self)
        self.menu.addAction(self.action1)
        self.menu.addAction(self.action2)

        # Connect the action triggers to emit the signal with the appropriate value
        self.action1.triggered.connect(lambda: self.circular_widget.circular_selector_changed.emit(1))
        self.action2.triggered.connect(lambda: self.circular_widget.circular_selector_changed.emit(2))

        # Create dropdown menu button
        self.menu_button = QPushButton("Menu", self)
        self.menu_button.setGeometry(0, 0, 70, 30)
        self.menu_button.setStyleSheet(
            """
            background: white;  /* Set background color to transparent */
            color: red;  /* Add a border for visibility */
            border-radius: 5px;
            padding: 5px 2px;
            """
        )
        self.menu_button.setMenu(self.menu)

        # Create close button
        self.close_button = QPushButton('X', self)
        self.close_button.setGeometry(72, 0, 20, 30)  # Set button position and size
        self.close_button.setStyleSheet(
            """
            background: white;  /* Set background color to transparent */
            color: red;  /* Add a border for visibility */
            border-radius: 5px;
            padding: 1px;
            """
        )
        self.close_button.clicked.connect(self.close)

        self.hidden_button = QPushButton('stop cap', self)
        self.hidden_button.setGeometry(350, 0, 50, 30)  # Set button position and size
        self.hidden_button.setStyleSheet(
            """
            background: red;  /* Set background color to transparent */
            color: green;  /* Add a border for visibility */
            border-radius: 50%;
            padding: 1px;
            """
        )
        self.hidden_button.clicked.connect(self.toggle_circular_selector)

    def toggle_circular_selector(self):
        self.circular_selector=2
        self.stopCaptureSignal.emit(2)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setCompositionMode(QPainter.CompositionMode_Clear)
        painter.fillRect(self.rect(), Qt.transparent)
        painter.setCompositionMode(QPainter.CompositionMode_SourceOver)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window=MainWindow()
    main_window.show()

    sys.exit(app.exec_())