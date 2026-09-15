import torch
import torch.nn as nn
import torch.nn.functional as F

class SEBlock(nn.Module):
    def __init__(self, channel, reduction=4):
        super(SEBlock, self).__init__()
        self.avg_pool = nn.AdaptiveAvgPool1d(1)
        self.fc = nn.Sequential(
            nn.Linear(channel, channel // reduction, bias=False),
            nn.ReLU(inplace=True),
            nn.Linear(channel // reduction, channel, bias=False),
            nn.Sigmoid()
        )
    def forward(self, x):
        b, c, _ = x.size()
        y = self.avg_pool(x).view(b, c)
        y = self.fc(y).view(b, c, 1)
        return x * y.expand_as(x)

class STAHN(nn.Module):
    def __init__(self, input_size=1, num_classes=2):
        super(STAHN, self).__init__()
        self.conv1 = nn.Conv1d(in_channels=input_size, out_channels=64, kernel_size=3, padding=1)
        self.se1 = SEBlock(64)
        self.pool1 = nn.MaxPool1d(2)
        
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3, padding=1)
        self.se2 = SEBlock(128)
        self.pool2 = nn.MaxPool1d(2)
        
        encoder_layer = nn.TransformerEncoderLayer(d_model=128, nhead=8, dim_feedforward=256, dropout=0.2, batch_first=True)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=2)
        
        self.lstm = nn.LSTM(input_size=128, hidden_size=256, num_layers=2, batch_first=True, bidirectional=True)
        
        self.fc1 = nn.Linear(256 * 2, 128)
        self.fc2 = nn.Linear(128, num_classes)
        self.dropout = nn.Dropout(0.4)

    def forward(self, x):
        x = x.permute(0, 2, 1)
        x = F.relu(self.se1(self.conv1(x)))
        x = self.pool1(x)
        x = F.relu(self.se2(self.conv2(x)))
        x = self.pool2(x)
        x = x.permute(0, 2, 1)
        x = self.transformer(x)
        lstm_out, _ = self.lstm(x)
        final_state = lstm_out[:, -1, :]
        out = F.relu(self.fc1(final_state))
        out = self.dropout(out)
        out = self.fc2(out)
        return out

print("✅ Clean STAHN model class loaded (no training code)")
