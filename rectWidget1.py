import sys
from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QPixmap, QImage, QPainter, QPainterPath, QMovie, QAction, QGradient, QColor, QFont, QBrush, QPalette
from PySide6.QtWidgets import QApplication, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QMainWindow, QMenu, QSizePolicy, QTableWidget, QTableWidgetItem, QScrollArea, QTextEdit, QHeaderView, QGraphicsOpacityEffect, QGraphicsDropShadowEffect

from tabulate import tabulate
from accuracyConfusionResult import AccuracyDialog, ConfusionMatrixDialog, ResultMatrixDialog
from pdf2image import convert_from_path
from PySide6.QtWebEngineWidgets import QWebEngineView
from rocWidget import ROCWidget

class RectangularWidget(QWidget):
    sniffStopped = Signal(bool)
    startTraining = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.result_selector = 2  # Set this value based on your logic
        self.widget_selector = 1
        self.model_selector = 1
        self.layout = QVBoxLayout(self)  # Use QVBoxLayout for vertical arrangement
        self.setLayout(self.layout)
        self.setFixedSize(400, 400)  # Set your desired size
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground)  # Set transparent background
        self.setStyleSheet("background:transparent;border:0;")
        self.packet_capture = None
        self.http = 0
        self.https = 0
        self.icmp = 0
        self.label1 = None
        self.scroll_area = QLabel(self)
        self.documentation_viewer=None
        self.images_container=None

        #shadow
        self.shadow_effect = QGraphicsDropShadowEffect()
        self.shadow_effect.setBlurRadius(20)
        self.shadow_effect.setColor(QColor(0, 0, 0, 150))  # Adjust opacity as desired
        self.shadow_effect.setOffset(10, 10)  # Adjust offset if needed

        # widget1
        self.update_widgets_static("Home")

        # widget2
        self.widget2_table = QTableWidget(self)
        self.widget2_table.setStyleSheet("""
            QTableWidget {
                background: qlineargradient(
                    spread:pad, x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(255, 230, 230, 255),
                    stop:1 rgba(250, 250, 250, 255)
                );
                border-radius: 12px;
                border: 1px solid rgba(209, 213, 219, 0.3);
                padding: 5px;
            }
            QHeaderView::section {
                background-color: rgba(255, 255, 255, 150);
                padding: 4px;
                border: 1px solid rgba(255, 255, 255, 150);
                border-radius: 5px;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 100, 150, 100);
            }
            """)
        self.widget2_table.setAlternatingRowColors(True)
        self.widget2_table.setColumnCount(4)
        self.widget2_table.setRowCount(1)
        self.widget2_table.setFixedSize(380, 100)
        self.widget2_table.setHorizontalHeaderLabels(["HTTP", "HTTPS", "ICMP", "Total"])
        self.widget2_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.widget2_table.verticalHeader().setVisible(False)  # Hide the row numbers
        self.widget2_table.setItem(0, 0, QTableWidgetItem(str(self.http)))
        self.widget2_table.setItem(0, 1, QTableWidgetItem(str(self.https)))
        self.widget2_table.setItem(0, 2, QTableWidgetItem(str(self.icmp)))
        self.widget2_table.setItem(0, 3, QTableWidgetItem(str(self.icmp + self.http + self.https)))
        self.widget2_table.resizeColumnsToContents()

        # Stop button
        self.widget2_stop_button = QPushButton("Stop Sniffing", self)
        self.widget2_stop_button.clicked.connect(self.stop_sniffing)
        self.widget2_stop_button.setFixedSize(150, 50)
        self.widget2_stop_button.setStyleSheet("""
            QPushButton {
                background: rgba(50, 55, 55, 250);
                border-radius: 10px;
                border: 1px solid rgba(255, 255, 255, 150);
                color:white;
            }
            """)

        # Start training button
        self.widget2_start_training = QPushButton("Start Training Models", self)
        self.widget2_start_training.clicked.connect(self.start_training)
        self.widget2_start_training.setFixedSize(150, 50)
        self.widget2_start_training.setStyleSheet("""
            QPushButton {
                background: rgba(200, 255, 200, 255);
                border-radius: 10px;
                border: 1px solid rgba(255, 255, 255, 150);
            }
            """)

        # Add widgets to layout
        self.layout.addWidget(self.widget2_table)
        self.layout.addWidget(self.widget2_stop_button)
        self.layout.addWidget(self.widget2_start_training)

        # Hide initially
        self.widget2_table.hide()
        self.widget2_stop_button.hide()
        self.widget2_start_training.hide()

        # widget3
        self.accuracy_label = QLabel("Accuracy", self)
        self.layout.addWidget(self.accuracy_label)
        self.accuracy_dialog = AccuracyDialog(accuracy=0.95)
        self.confusion_matrix_dialog = ConfusionMatrixDialog(confusion_matrix=[[1, 2], [3, 4]])
        self.result_matrix_dialog = ResultMatrixDialog(result_matrix=[[5, 6], [7, 8]])
        self.accuracy_label.hide()

        #roc curve
        # Initialize ROCCurveWidget
        self.roc_curve_widget = ROCWidget(self)
        self.current_graph_widget = None  # Track the current graph widget
        # Add the widget to layout
        self.layout.addWidget(self.roc_curve_widget)
        self.setLayout(self.layout)
        self.roc_curve_widget.hide()
    def update_roc_curve(self, model_names, models, X_test, y_test):
        # Hide the previous graph widget if it exists
        if self.current_graph_widget:
            self.current_graph_widget.hide()

        # Set data for ROCCurveWidget
        self.roc_curve_widget.set_data(model_names, models, X_test, y_test)

        # Update the current graph widget reference
        self.current_graph_widget = self.roc_curve_widget

        # Show the new graph widget
        self.roc_curve_widget.show()

    def start_training(self):
        self.startTraining.emit(True)

    def set_accuracy_confusion_result(self, accuracy, confusion, result):
        self.accuracy_dialog = accuracy
        self.confusion_matrix_dialog = confusion
        self.result_matrix_dialog = result

    def update_widgets_static(self, tab):
        self.scroll_area.setGraphicsEffect(None)
        print(tab, ":rect-widget")
        try:
            self.accuracy_label.hide()
            self.widget2_table.hide()
            self.widget2_stop_button.hide()
            self.images_layout.hide()
            self.documentation_viewer.hide()
            self.roc_curve_widget.hide()  # Hide ROCWidget when switching tabs
        except AttributeError as e:
            print("Error:", e)

        if tab == "Home":
            if self.documentation_viewer:
                self.documentation_viewer.hide()
            if self.images_container:
                self.images_container.hide()
            self.scroll_area.show()
            image_path = "homeimage.jpeg"  # Replace with your image path
            image = QImage(image_path)
            pixmap = QPixmap.fromImage(image)
            pixmap = pixmap.scaled(self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.scroll_area.setPixmap(pixmap)
            self.scroll_area.setFixedSize(400, 400)  # Set the size of the QLabel

        elif tab == "Documentation":
            self.scroll_area.hide()
            # Create QScrollArea
            self.documentation_viewer = QScrollArea(self)
            self.layout.addWidget(self.documentation_viewer)

            self.images_container = QWidget()
            self.images_layout = QVBoxLayout(self.images_container)
            self.images_container.setLayout(self.images_layout)
            self.documentation_viewer.setWidget(self.images_container)
            self.documentation_viewer.setWidgetResizable(True)

            # Convert the PDF to a list of PIL images
            images = convert_from_path("doc.pdf")
            # print(images)

            # Create QLabel for each image and add it to the layout
            for image in images:
                label = QLabel(self)
                # Convert PIL image to QImage
                qimage = QImage(image.tobytes(), image.width, image.height, QImage.Format_RGB888)
                # Scale the QImage to fit within 400x400 while maintaining aspect ratio
                qimage = qimage.scaled(400, 400, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                pixmap = QPixmap.fromImage(qimage)
                label.setPixmap(pixmap)
                label.setScaledContents(True)  # Ensure the image is scaled to fit the label
                label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)  # Set size policy
                self.images_layout.addWidget(label)

            # Adjust size of QScrollArea to the size of its contents
            self.documentation_viewer.adjustSize()
        elif tab == "About us":
            if self.documentation_viewer:
                self.documentation_viewer.hide()
            if self.images_container:
                self.images_container.hide()
            self.scroll_area.show()
            image_path = "about.png"  # Replace with your image path
            image = QImage(image_path)
            pixmap = QPixmap.fromImage(image)
            pixmap = pixmap.scaled(self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.scroll_area.setPixmap(pixmap)
            self.scroll_area.setFixedSize(400, 400)  # Set the size of the QLabel


    def receive_start_sniffing(self):
        self.widget_selector = 2
        self.model_selector = 0
        self.update_widgets()

    def update_widgets(self):
        if self.widget_selector == 1:
            self.label1.setText("This is home page")
            self.scroll_area.show()
            self.accuracy_dialog.hide()
            self.confusion_matrix_dialog.hide()
            self.result_matrix_dialog.hide()
            self.widget2_table.hide()
            self.widget2_stop_button.hide()
            self.roc_curve_widget.hide()  # Hide ROCWidget when switching to Home tab
        elif self.widget_selector == 2:
            if self.label1:
                self.label1.hide()
            if self.scroll_area:
                self.scroll_area.hide()
            if self.widget2_start_training:
                self.widget2_start_training.hide()
            if self.documentation_viewer:
                self.documentation_viewer.hide()
            if self.model_selector == 0:
                self.widget2_table.show()
                self.widget2_stop_button.show()
                self.layout.addWidget(self.widget2_table)
                self.layout.addWidget(self.widget2_stop_button)
            else:
                self.widget2_table.hide()
                self.widget2_stop_button.hide()
                self.roc_curve_widget.hide()  # Hide ROCWidget when switching to Models tab
                if self.model_selector == 1:
                    head = "Random Forest:"
                elif self.model_selector == 2:
                    head = "Logistics Regression:"
                elif self.model_selector == 3:
                    head = "MLP:"
                elif self.model_selector == 4:
                    head = "LSTM:"

                accuracy_text = f"Accuracy: {self.accuracy_dialog}\n\n"
                confusion_text = f"Confusion Matrix:\n{self.confusion_matrix_dialog}\n\n"
                result_text = f"Classification Report:\n{self.result_matrix_dialog}"
                info_text = f"{head}\n\n{accuracy_text}{confusion_text}{result_text}"
                self.accuracy_label.setStyleSheet("""
                    background: qlineargradient(
                    spread:pad, x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(55, 30, 30, 255),
                    stop:1 rgba(155, 130, 150, 250)
                    );
                    border-radius: 10px;
                    border: 1px solid rgba(255, 255, 255, 200);
                    padding: 10px;
                    color:white;
                    """)
                self.accuracy_label.setText(info_text)
                self.accuracy_label.show()


    def set_packet_capture(self, packet_capture):
        self.packet_capture = packet_capture

    def update_capture_info(self, http_count, https_count, icmp_count, counter):
        self.http = http_count
        self.https = https_count
        self.icmp = icmp_count
        self.widget2_table.setItem(0, 0, QTableWidgetItem(str(self.http)))
        self.widget2_table.setItem(0, 1, QTableWidgetItem(str(self.https)))
        self.widget2_table.setItem(0, 2, QTableWidgetItem(str(self.icmp)))
        self.widget2_table.setItem(0, 3, QTableWidgetItem(str(self.http + self.https + self.icmp)))

    def stop_sniffing(self):
        print("stop sniffing called in rect widget")
        self.widget2_stop_button.hide()
        self.widget2_start_training.show()
        self.sniffStopped.emit(True)

    def receive_click_home(self, text):
        if text == "Home":
            self.web_view = QWebEngineView()
            filename = "readme.html"
            url = QUrl.fromLocalFile(filename)
            self.web_view.load(url)
            self.label1.addWidget(self.web_view)
            self.show()

    def receive_submenu_value(self, cws, ms, accuracy, conf_matrix, result_matrix):
        print("rectWidget received signal:", cws, ms, accuracy)
        self.widget_selector = cws
        self.model_selector = ms
        self.set_accuracy_confusion_result(accuracy, conf_matrix, result_matrix)
        self.update_widgets()

        # Hide the previous graph widget if it exists
        if self.current_graph_widget:
            self.current_graph_widget.hide()
            self.current_graph_widget = None
