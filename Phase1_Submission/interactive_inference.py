import os
import sys

print("[*] Booting STAHN Deep Learning Environment...")
try:
    import torch
    import torch.nn as nn
    import pandas as pd
    import numpy as np
    from sklearn.preprocessing import StandardScaler
except ImportError as e:
    print(f"[!] Missing dependency: {e}. Please ensure pip installed everything.")
    sys.exit(1)

# 1. Mathematically reconstruct the STAHN architecture
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
        self.pool1 = nn.MaxPool1d(kernel_size=2)
        
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3, padding=1)
        self.se2 = SEBlock(128)
        self.pool2 = nn.MaxPool1d(kernel_size=2)
        
        encoder_layer = nn.TransformerEncoderLayer(d_model=128, nhead=8, dim_feedforward=256, dropout=0.2, batch_first=True)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=2)
        
        self.lstm = nn.LSTM(input_size=128, hidden_size=256, num_layers=2, batch_first=True, bidirectional=True)
        
        self.fc1 = nn.Linear(256 * 2, 128)
        self.fc2 = nn.Linear(128, num_classes)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        import torch.nn.functional as F
        x = x.permute(0, 2, 1)
        
        # Block 1
        x = F.relu(self.conv1(x))
        x = self.se1(x)
        x = self.pool1(x)
        
        # Block 2
        x = F.relu(self.conv2(x))
        x = self.se2(x)
        x = self.pool2(x)
        
        x = x.permute(0, 2, 1)
        
        # Transformer
        x = self.transformer(x)
        
        # LSTM
        lstm_out, _ = self.lstm(x)
        final_state = lstm_out[:, -1, :]
        
        # FC
        out = F.relu(self.fc1(final_state))
        out = self.dropout(out)
        out = self.fc2(out)
        return out

# 2. Load Model Weights (Using CPU so it works on any Windows laptop)
print("[*] Loading World-Record Weights (stahn_model.pth)...")
device = torch.device('cpu')
model = STAHN().to(device)
try:
    model.load_state_dict(torch.load('stahn_model.pth', map_location=device))
    model.eval()
except Exception as e:
    print(f"[!] Failed to load weights: {e}")
    input("Press Enter to exit...")
    sys.exit(1)

# 3. Fit a Global Scaler using the Sample Dataset
# (You cannot calculate Variance on a single packet, so we use the sample dataset to anchor the math)
print("[*] Calibrating Mathematical Variance Anchors...")
try:
    sample_df = pd.read_csv('CICIoT2023_Sample.csv')
    
    # Extract labels
    target_col = 'Label' if 'Label' in sample_df.columns else 'label' if 'label' in sample_df.columns else None
    if sample_df[target_col].dtype == 'O' or sample_df[target_col].dtype == 'string':
        y_sample = sample_df[target_col].apply(lambda x: 0 if x == 'BenignTraffic' else 1).values
    else:
        y_sample = sample_df[target_col].values
        
    cols_to_drop = [col for col in ['label', 'Label', 'attack_class'] if col in sample_df.columns]
    X_sample_raw = sample_df.drop(columns=cols_to_drop).select_dtypes(exclude=['object', 'string']).values
    
    X_sample_raw = np.where(np.isinf(X_sample_raw.astype(float)), np.nan, X_sample_raw.astype(float))
    X_sample_raw = np.nan_to_num(X_sample_raw, nan=0.0)
    
    scaler = StandardScaler()
    scaler.fit(X_sample_raw)
except Exception as e:
    print(f"[!] Failed to calibrate scaler: {e}")
    input("Press Enter to exit...")
    sys.exit(1)

print("\n==================================================")
print("     STAHN IDS: INTERACTIVE TERMINAL ACTIVE")
print("==================================================")

while True:
    print("\n[Options]")
    print("1. Pick a RANDOM network packet from the Sample CSV to test.")
    print("2. Paste 46 comma-separated features manually.")
    print("3. Exit")
    choice = input("Enter your choice (1, 2, or 3): ").strip()
    
    if choice == '3':
        break
        
    packet_features = None
    true_label = None
    
    if choice == '1':
        # Pick random row
        idx = np.random.randint(0, len(X_sample_raw))
        packet_features = X_sample_raw[idx]
        true_label = "ATTACK (1)" if y_sample[idx] == 1 else "BENIGN (0)"
        print(f"\n[*] Extracted Packet #{idx} from Sample CSV.")
        
    elif choice == '2':
        raw_str = input("\nPaste exactly 46 comma-separated numbers: ").strip()
        try:
            packet_features = np.array([float(x.strip()) for x in raw_str.split(',')])
            if len(packet_features) != X_sample_raw.shape[1]:
                print(f"[!] Error: Expected {X_sample_raw.shape[1]} features, got {len(packet_features)}.")
                continue
            true_label = "UNKNOWN (Manual Input)"
        except ValueError:
            print("[!] Error: Invalid numerical input.")
            continue
    else:
        print("[!] Invalid choice.")
        continue
        
    # --- INFERENCE PIPELINE ---
    # 1. Scale
    packet_features = np.where(np.isinf(packet_features), np.nan, packet_features)
    packet_features = np.nan_to_num(packet_features, nan=0.0)
    packet_scaled = scaler.transform([packet_features]) # Transform expects 2D array
    
    # 2. Reshape to 3D Tensor (batch=1, features=46, channels=1)
    tensor_input = torch.FloatTensor(packet_scaled.reshape(1, -1, 1)).to(device)
    
    # 3. Predict
    with torch.no_grad():
        output = model(tensor_input)
        prob = torch.softmax(output, dim=1)[0, 1].item()
        pred = int(torch.argmax(output, dim=1).item())
        
    pred_str = "ATTACK" if pred == 1 else "BENIGN"
    confidence = (prob if pred == 1 else (1.0 - prob)) * 100
    
    print("--------------------------------------------------")
    print(f" TRUE LABEL       : {true_label}")
    print(f" STAHN PREDICTION : {pred_str} (Confidence: {confidence:.2f}%)")
    print("--------------------------------------------------")
    
    if true_label != "UNKNOWN (Manual Input)":
        if (pred == 1 and y_sample[idx] == 1) or (pred == 0 and y_sample[idx] == 0):
            print(" [+] SUCCESS: The Model accurately identified the traffic!")
        else:
            print(" [!] FAILURE: The Model made an incorrect prediction.")
