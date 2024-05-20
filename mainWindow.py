import sys
from circularWidget import CircularImageWidget
from rectWidget1 import RectangularWidget
from packetCapture import PacketCapture
from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QPixmap, QImage, QPainter, QPainterPath, QMovie, QAction
from PySide6.QtWidgets import QApplication, QWidget, QHBoxLayout, QLabel, QPushButton, QMainWindow, QMenu, QSizePolicy


class MainWindow(QMainWindow):
    submenuClicked=Signal(int,int,int,str,str)
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        w = 800
        h = 400
        self.resize(w, h)
        self.packet_capture = PacketCapture()

        self.circular_widget=CircularImageWidget(self)
        self.rect_widget=RectangularWidget(self)
        self.layout=QHBoxLayout()
        self.layout.addWidget(self.circular_widget)
        self.layout.addWidget(self.rect_widget)
        central_widget = QWidget()
        central_widget.setLayout(self.layout)
        
        self.setCentralWidget(central_widget)
        self.close_button = QPushButton('X', self)
        self.close_button.setGeometry(72, 0, 70, 30)  # Set button position and size
        self.close_button.setStyleSheet(
            """
            background: red;  /* Set background color to transparent */
            color: white;  /* Add a border for visibility */
            border-radius: 5px;
            padding: 1px;
            """
        )
        self.close_button.clicked.connect(self.close)

        # Create dropdown menu button
        self.menu = QMenu()
        # Set background color
        self.menu.setStyleSheet("""
            QMenu {
                background-color: #22FFFF;
            }
            QMenu::item {
                padding: 5px 15px;
                border-radius: 5px;
                color: #333;
            }
            QMenu::item:selected {
                background-color: yellow;
            }
        """)
        action1=self.menu.addAction("Home")
        action2=self.menu.addAction("Models")
        action3=self.menu.addAction("Documentation")
        action4=self.menu.addAction("About us")
        action1.triggered.connect(lambda: self.submenu_triggered(action1))
        action3.triggered.connect(lambda: self.submenu_triggered(action3))
        action4.triggered.connect(lambda: self.submenu_triggered(action4))


        # Create a submenu for action3
        submenu = QMenu("Submenu")
        submenu.addAction("Random Forest")
        submenu.addAction("Logistics Regression")
        submenu.addAction("MLP")
        submenu.addAction("LSTM")
        submenu.triggered.connect(self.submenu_triggered)

        # Add the submenu to action3
        action2.setMenu(submenu)

        action5=self.menu.addAction("Graphs")
        # Create a submenu for action3
        submenu1 = QMenu("Submenu")
        submenu1.addAction("Random Forest")
        submenu1.addAction("Logistics Regression")
        submenu1.addAction("MLP")
        submenu1.addAction("LSTM")
        action5.setMenu(submenu1)
        submenu1.triggered.connect(self.graph_menu_triggered)


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

        # Set the PacketCapture instance for CircularImageWidget
        self.circular_widget.set_packet_capture(self.packet_capture)
        self.rect_widget.set_packet_capture(self.packet_capture)

        self.circular_widget.jpegClicked.connect(self.start_packet_capture)

        # Connect the signal to the slot
        self.packet_capture.packet_counts_updated.connect(self.rect_widget.update_capture_info)
        self.rect_widget.sniffStopped.connect(self.packet_capture.stop_sniffing)
        self.rect_widget.sniffStopped.connect(self.circular_widget.receive_stop_sniff)
        self.rect_widget.startTraining.connect(self.packet_capture.train_with_new_data)

    def start_packet_capture(self):
        self.packet_capture.start_sniffing()
        self.rect_widget.receive_start_sniffing()
    def closeEvent(self, event):
        self.packet_capture.stop_sniffing()
        event.accept()
    def click_home(self,action):
        text=action.text()
        self.rect_widget.receive_click_home(text)
    def graph_menu_triggered(self,action):
        self.rect_widget.accuracy_label.hide()
        # Plot the ROC curve for the selected model
        if action.text() == "Random Forest":
            print("Plotting ROC curve for Random Forest")
            fpr,tpr=self.packet_capture.roc_data["rf"];
            
        elif action.text() == "Logistics Regression":
            print("Plotting ROC curve for Logistics Regression")
            fpr,tpr=self.packet_capture.roc_data["lr"];
        elif action.text() == "MLP":
            fpr,tpr=self.packet_capture.roc_data["mlp"];
        elif action.text() == "LSTM":
            print("Plotting ROC curve for LSTM")
            fpr,tpr=self.packet_capture.roc_data["lstmpytorch"];
        self.rect_widget.roc_curve_widget.show()
        self.rect_widget.roc_curve_widget.plot_roc_curve(fpr,tpr,action.text())

    def submenu_triggered(self, action):
        # Check if the triggered action is "Random Forest"
        data=self.packet_capture.load_data("https4.csv")
        X_train, X_test, y_train, y_test=self.packet_capture.preprocess_data_imputed(self.packet_capture.data)
        if action.text() == "Random Forest":
            accuracy, conf_matrix, class_report=self.packet_capture.train_evaluate_random_forest(X_train, X_test, y_train, y_test)
            # Emit a signal or perform any action you want
            # For example, you can emit a custom signal with the desired value
            print("main window-accuracy-rf:",accuracy)
            self.submenuClicked.emit(2,1,accuracy,conf_matrix,class_report)
            #self.submenuClicked.connect(self.rect_widget.receive_submenu_value)
            self.rect_widget.receive_submenu_value(2,1,accuracy,conf_matrix,class_report)
        elif action.text()=="Logistics Regression":
            accuracy, conf_matrix, class_report=self.packet_capture.train_evaluate_logistic_regression(X_train, X_test, y_train, y_test)
            # Emit a signal or perform any action you want
            # For example, you can emit a custom signal with the desired value
            print("main window-accuracy-lr:",accuracy)
            self.submenuClicked.emit(2,2,accuracy,conf_matrix,class_report)
            #self.submenuClicked.connect(self.rect_widget.receive_submenu_value)
            self.rect_widget.receive_submenu_value(2,2,accuracy,conf_matrix,class_report)
        elif action.text()=="MLP":
            accuracy, conf_matrix, class_report=self.packet_capture.train_evaluate_mlp_classifier(X_train, X_test, y_train, y_test)
            # Emit a signal or perform any action you want
            # For example, you can emit a custom signal with the desired value
            print("main window-accuracy-mlp:",accuracy)
            self.submenuClicked.emit(2,3,accuracy,conf_matrix,class_report)
            #self.submenuClicked.connect(self.rect_widget.receive_submenu_value)
            self.rect_widget.receive_submenu_value(2,3,accuracy,conf_matrix,class_report)
        elif action.text()=="LSTM":

            accuracy, conf_matrix, class_report=self.packet_capture.train_evaluate_lstm_pytorch(X_train, X_test, y_train, y_test)
            # Emit a signal or perform any action you want
            # For example, you can emit a custom signal with the desired value
            print("main window-accuracy-lstm:",accuracy)
            self.submenuClicked.emit(2,4,accuracy,conf_matrix,class_report)
            #self.submenuClicked.connect(self.rect_widget.receive_submenu_value)
            self.rect_widget.receive_submenu_value(2,4,accuracy,conf_matrix,class_report)
        elif (action.text()=="Home" or action.text()=="Documentation" or action.text()=="About us"):
            print(action.text())
            self.rect_widget.update_widgets_static(action.text())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window=MainWindow()
    main_window.show()

    sys.exit(app.exec())