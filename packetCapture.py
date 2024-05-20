from scapy.all import sniff, TCP, IP, ICMP
from PySide6.QtCore import Signal, QObject
from threading import Thread, Event
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, roc_curve, auc
from sklearn.preprocessing import LabelEncoder
from imblearn.under_sampling import RandomUnderSampler
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.impute import SimpleImputer
import torch
import torch.nn as nn
import torch.optim as optim
from lstm import LSTMModel
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
from PySide6.QtWidgets import QVBoxLayout, QWidget

class PacketCapture(QObject):
    # Define a signal to emit updated packet counts
    packet_counts_updated = Signal(int, int, int, int)

    def __init__(self):
        super().__init__()
        self.stop_event = Event()
        self.roc_data={}
        self.packets = []
        self.http_count = 0
        self.https_count = 0
        self.icmp_count = 0
        self.running = False
        self.counter = 0
        self.count = 0
        self.num_failed_logins = 0
        self.num_compromised = 0
        self.start_time = None
        self.sniff_thread = None  # Initialize sniff_thread here
        self.data = self.load_data("https4.csv")
        self.new_data=None
        self.X_train, self.X_test, self.y_train, self.y_test = self.preprocess_data(self.data)

    def packet_callback(self, packet):
        if packet.haslayer(TCP) and packet[TCP].dport == 80:
            self.http_count += 1
        elif packet.haslayer(TCP) and packet[TCP].dport == 443:
            self.https_count += 1
        elif packet.haslayer(ICMP):
            self.icmp_count += 1
        else:
            return

        if (self.http_count + self.https_count + self.icmp_count) == 1:
            print("| {:^10} | {:^10} | {:^10} | {:^10} |".format("HTTP", "HTTPS", "ICMP", "Total"))
            print("-" * 53)
        print("| {:^10} | {:^10} | {:^10} | {:^10} |".format(self.http_count, self.https_count, self.icmp_count, self.counter), end="\r", flush=True)

        raw = packet.show(dump=True)
        data = {}
        self.counter += 1
        self.packet_counts_updated.emit(self.http_count, self.https_count, self.icmp_count, self.counter)

        if 'login failed' in str(packet.payload).lower():
            self.num_failed_logins += 1
        elif 'compromised' in str(packet.payload).lower():
            self.num_compromised += 1
        data["num_failed_logins"] = self.num_failed_logins
        data["num_compromised"] = self.num_compromised
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            is_urgent_set = (tcp_flags & 0x40) != 0
            data["urgent"] = 1 if is_urgent_set else 0
            is_mf_set = (tcp_flags & 0x80) != 0
            fragment_offset = packet[TCP].seq
            if is_mf_set and fragment_offset != 0:
                data["wrong_fragment"] = 1
            else:
                data["wrong_fragment"] = 0

        if not self.start_time:
            self.start_time = packet.time
        else:
            duration = packet.time - self.start_time
            data["duration"] = duration
            self.start_time = None
        if IP in packet:
            src_bytes = len(packet[IP].payload)
            dst_bytes = len(packet[IP])

            data["src_bytes"] = src_bytes
            data["dst_bytes"] = dst_bytes

        for line in raw.splitlines():
            line = line.strip()
            if (not line.startswith("###[") and not line.endswith("]###")) and not line.find("\\options") >= 0:
                try:
                    key, value = line.split("=", 1)
                except ValueError:
                    continue
                key = key.strip().lower()
                value = value.strip()
                data[key] = value
                data["class"] = "normal"
            self.packets.append(data)

    def start_sniffing(self):
        self.stop_event.clear()
        self.sniff_thread = Thread(target=self.packet_callback_threaded)
        self.sniff_thread.start()

    def packet_callback_threaded(self):
        sniff(prn=self.packet_callback, stop_filter=lambda x: self.stop_event.is_set(), count=0)

    def stop_sniffing(self):
        self.stop_event.set()
        if self.sniff_thread is not None and self.sniff_thread.is_alive():
            self.sniff_thread.join()
        print("stop sniffing called in packet capture")

    def load_data(self, csv_file):
        data = pd.read_csv(csv_file, delimiter=',', quotechar='"', low_memory=False)
        return data

    def preprocess_data(self, data):
        data.drop_duplicates(inplace=True)
        data.loc[data["class"] == "normal", "class"] = 0
        data.loc[data["class"] == "anomaly", "class"] = 1

        label_encoder = LabelEncoder()
        for column in data.select_dtypes(include=['object', 'category']):
            data[column] = label_encoder.fit_transform(data[column])

        le = LabelEncoder()
        le.fit(data["class"])
        data["class"] = le.transform(data["class"])

        rus = RandomUnderSampler(sampling_strategy='majority')
        X_resampled, y_resampled = rus.fit_resample(data.drop(columns=["class"]), data["class"])

        X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, random_state=42)

        return X_train, X_test, y_train, y_test

    def train_evaluate_random_forest(self, X_train, X_test, y_train, y_test):
        model = RandomForestClassifier(random_state=42)
        model.fit(X_train, y_train)

        #roc curve feed
        # Get predicted probabilities for positive class
        y_scores = model.predict_proba(X_test)[:, 1]
        # Compute ROC curve
        fpr, tpr, _ = roc_curve(y_test, y_scores)
        self.roc_data["rf"]=(fpr,tpr)

        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        conf_matrix = confusion_matrix(y_test, y_pred)
        class_report = classification_report(y_test, y_pred)

        return accuracy, conf_matrix, class_report

    def train_evaluate_logistic_regression(self, X_train, X_test, y_train, y_test):
        model = LogisticRegression(C=0.001, penalty='l1', solver='liblinear')
        model.fit(X_train, y_train)

        #roc curve feed
        # Get predicted probabilities for positive class
        y_scores = model.predict_proba(X_test)[:, 1]
        # Compute ROC curve
        fpr, tpr, _ = roc_curve(y_test, y_scores)
        self.roc_data["lr"]=(fpr,tpr)

        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        conf_matrix = confusion_matrix(y_test, y_pred)
        class_report = classification_report(y_test, y_pred)

        return accuracy, conf_matrix, class_report

    def train_evaluate_mlp_classifier(self, X_train, X_test, y_train, y_test):
        model = MLPClassifier(hidden_layer_sizes=(100,), activation='relu', solver='adam', max_iter=1000)
        model.fit(X_train, y_train)

        #roc curve feed
        # Get predicted probabilities for positive class
        y_scores = model.predict_proba(X_test)[:, 1]
        # Compute ROC curve
        fpr, tpr, _ = roc_curve(y_test, y_scores)
        self.roc_data["mlp"]=(fpr,tpr)

        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        conf_matrix = confusion_matrix(y_test, y_pred)
        class_report = classification_report(y_test, y_pred)

        return accuracy, conf_matrix, class_report

    def train_evaluate_lstm(self, X_train, X_test, y_train, y_test):
        X_train_lstm = X_train.to_numpy().reshape((X_train.shape[0], 1, X_train.shape[1]))
        X_test_lstm = X_test.to_numpy().reshape((X_test.shape[0], 1, X_test.shape[1]))

        model_lstm = Sequential()
        model_lstm.add(LSTM(50, return_sequences=True, input_shape=(X_train_lstm.shape[1], X_train_lstm.shape[2])))
        model_lstm.add(LSTM(50, return_sequences=True))
        model_lstm.add(LSTM(50))
        model_lstm.add(Dense(1, activation='sigmoid'))
        model_lstm.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
        model_lstm.fit(X_train_lstm, y_train, epochs=25, batch_size=32)

        y_pred_lstm = model_lstm.predict(X_test_lstm)
        y_pred_lstm = (y_pred_lstm > 0.5)
        accuracy = accuracy_score(y_test, y_pred_lstm)
        conf_matrix = confusion_matrix(y_test, y_pred_lstm)
        class_report = classification_report(y_test, y_pred_lstm)

        return accuracy, conf_matrix, class_report

    def train_evaluate_lstm_pytorch(self, X_train, X_test, y_train, y_test):
        input_size = X_train.shape[1]
        model = LSTMModel(input_size)

        criterion = nn.BCELoss()
        optimizer = optim.Adam(model.parameters(), lr=0.001)

        X_train_lstm = torch.from_numpy(X_train.to_numpy()).float().unsqueeze(1)
        X_test_lstm = torch.from_numpy(X_test.to_numpy()).float().unsqueeze(1)
        y_train_tensor = torch.from_numpy(y_train.values).float().view(-1, 1)
        y_test_tensor = torch.from_numpy(y_test.values).float().view(-1, 1)

        epochs = 25
        batch_size = 32
        for epoch in range(epochs):
            model.train()
            optimizer.zero_grad()
            outputs = model(X_train_lstm)
            loss = criterion(outputs, y_train_tensor)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            y_pred_tensor = model(X_test_lstm)
            y_pred = (y_pred_tensor > 0.5).numpy()
            y_pred_probs = torch.sigmoid(y_pred_tensor).numpy()
        
        # Compute ROC curve
        fpr, tpr, _ = roc_curve(y_test, y_pred_probs)

        # Store ROC data
        self.roc_data['lstmpytorch'] = (fpr, tpr)

        accuracy = accuracy_score(y_test, y_pred)
        conf_matrix = confusion_matrix(y_test, y_pred)
        class_report = classification_report(y_test, y_pred)

        return accuracy, conf_matrix, class_report
    def select_random_anomalies(self,df, n):
        # Filter the DataFrame to only include rows with class="anomaly"
        anomaly_df = df[df['class'] == 1]

        # Check if there are enough anomaly rows
        if n > len(anomaly_df):
            print(f"Warning: There are only {len(anomaly_df)} anomaly rows in the DataFrame. Selecting all of them.")
            return anomaly_df

        # Randomly select n rows from the anomaly DataFrame
        return anomaly_df.sample(n, random_state=42)  # Set random_state for reproducibility
    def train_with_new_data(self):
        df=pd.DataFrame(self.packets)
        df.drop_duplicates(inplace=True)
        common_columns = set(self.data.columns) & set(df.columns)
        anomaly_data = self.select_random_anomalies(self.data,len(df))
        df_filtered = df.drop(columns=[col for col in df.columns if col not in common_columns])
        self.new_data = pd.concat([df_filtered, anomaly_data])
        print(self.new_data)
        self.data=self.new_data

    def preprocess_data_updated(self,data):
        # Create a label encoder instance
        label_encoder = LabelEncoder()

        for column in data.columns:
            if data[column].dtype == object:
                # Check for mixed types
                if data[column].apply(lambda x: isinstance(x, str)).any() and data[column].apply(lambda x: isinstance(x, int)).any():
                    # Convert all to string
                    data[column] = data[column].astype(str)
            elif data[column].dtype == 'int64' or data[column].dtype == 'float64':
                continue  # Skip numerical columns
            else:
                # If it's not an object or numerical column, convert to string just in case
                data[column] = data[column].astype(str)

            # Apply label encoding
            if data[column].dtype == object:
                data[column] = label_encoder.fit_transform(data[column])

        # Split the data into features and labels (assuming 'label' is the target column)
        X = data.drop('class', axis=1)
        y = data['class']

        # Split the data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        return X_train, X_test, y_train, y_test

    def preprocess_data_imputed(self, data):
        # Drop columns that are completely empty
        data = data.dropna(axis=1, how='all')

        # Separate columns by type
        numerical_columns = data.select_dtypes(include=['int64', 'float64']).columns
        categorical_columns = data.select_dtypes(include=['object']).columns

        # Convert mixed-type columns to strings
        for column in data.columns:
            if data[column].apply(lambda x: isinstance(x, (int, float, str))).all():
                if data[column].apply(lambda x: isinstance(x, str)).any() and data[column].apply(lambda x: isinstance(x, (int, float))).any():
                    data[column] = data[column].astype(str)

        # Impute missing values for numerical columns
        if not numerical_columns.empty:
            num_imputer = SimpleImputer(strategy='mean')
            data[numerical_columns] = num_imputer.fit_transform(data[numerical_columns])

        # Impute missing values for categorical columns
        if not categorical_columns.empty:
            cat_imputer = SimpleImputer(strategy='most_frequent')
            data[categorical_columns] = cat_imputer.fit_transform(data[categorical_columns])

        # Create a label encoder instance
        label_encoder = LabelEncoder()

        for column in data.columns:
            if data[column].dtype == object:
                # Apply label encoding
                data[column] = label_encoder.fit_transform(data[column])

        # Ensure there is a target column 'label' to drop and use as labels
        if 'class' not in data.columns:
            raise ValueError("Target column 'class' not found in data")

        # Split the data into features and labels (assuming 'label' is the target column)
        X = data.drop('class', axis=1)
        y = data['class']

        # Split the data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        return X_train, X_test, y_train, y_test
    def plot_roc_curve_in_widget(self, model_name, inner_rect_widget):
        if model_name not in self.roc_data:
            print(f"No ROC data available for model '{model_name}'")
            return

        fpr, tpr = self.roc_data[model_name]

        # Create a Matplotlib figure and canvas
        fig, ax = plt.subplots()
        ax.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve')
        ax.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        ax.set_xlabel('False Positive Rate')
        ax.set_ylabel('True Positive Rate')
        ax.set_title(f'ROC Curve - {model_name}')
        ax.legend(loc="lower right")

        # Clear layout of inner_rect_widget
        inner_rect_widget.clearLayout()

        # Create a new layout and add the canvas to it
        layout = QVBoxLayout()
        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)

        # Set the new layout to inner_rect_widget
        inner_rect_widget.setLayout(layout)

        # Ensure the plot is displayed
        canvas.draw()

        print("ROC curve plotted successfully for model:", model_name)


