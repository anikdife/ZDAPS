import torch.nn as nn

class LSTMModel(nn.Module):
    def __init__(self, input_size):
        super(LSTMModel, self).__init__()
        self.lstm1 = nn.LSTM(input_size, 50, batch_first=True)
        self.lstm2 = nn.LSTM(50, 50, batch_first=True)
        self.lstm3 = nn.LSTM(50, 50, batch_first=True)
        self.fc = nn.Linear(50, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out, _ = self.lstm1(x)
        out, _ = self.lstm2(out)
        out, _ = self.lstm3(out)
        out = self.fc(out[:, -1, :])  # Get the last output of the sequence
        out = self.sigmoid(out)
        return out


