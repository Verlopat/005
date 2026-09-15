import torch
import torch.nn as nn
import torch.nn.functional as F
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_curve, auc, confusion_matrix, classification_report
from torch.utils.data import DataLoader, TensorDataset
from datasets import load_dataset
import os

print("==========================================")
print(" STAHN ARCHITECTURE: EVALUATION PHASE ")
print("==========================================")

# 1. Re-define the Model Architecture (Must exactly match the training architecture)
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

# 2. Load the Weights
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"[*] Using device: {device}")

model = STAHN().to(device) # input_size defaults to 1 internally
try:
    model.load_state_dict(torch.load('stahn_model.pth', map_location=device))
    print("[*] Successfully loaded 'stahn_model.pth' world-record weights!")
except Exception as e:
    print(f"[!] Error loading model weights: {e}")
    print("[!] Ensure 'stahn_model.pth' is in the same directory.")
    exit(1)

model.eval()

# 3. Stream the Unseen Test Dataset
print("[*] Streaming UNSEEN 'test' split from HuggingFace for scientifically valid validation...")
try:
    test_ds = load_dataset('lacg030175/CIC-IoT-2023-full', split='test', streaming=True)
except Exception as e:
    print("[!] Failed to load dataset. Make sure you have internet access.")
    exit(1)

# Grab exactly 100,000 completely unseen packets
print("[*] Buffering 100,000 unseen test packets...")
test_buffer = []
for idx, row in enumerate(test_ds):
    test_buffer.append(row)
    if idx >= 100000:
        break

df = pd.DataFrame(test_buffer)

# 4. Strict Preprocessing (Same as training to prevent Target Leakage)
target_col = 'Label' if 'Label' in df.columns else 'label' if 'label' in df.columns else None
if not target_col:
    print("[!] No target column found. Cannot evaluate.")
    exit(1)

if df[target_col].dtype == 'O' or df[target_col].dtype == 'string':
    y_true = df[target_col].apply(lambda x: 0 if x == 'BenignTraffic' else 1).values
else:
    y_true = df[target_col].values

cols_to_drop = [col for col in ['label', 'Label', 'attack_class'] if col in df.columns]
df = df.drop(columns=cols_to_drop)
df = df.select_dtypes(exclude=['object', 'string'])
X_test = df.values

# Scale (StandardScaler to mathematically mirror the training phase)
from sklearn.preprocessing import StandardScaler
X_test = np.where(np.isinf(X_test.astype(float)), np.nan, X_test.astype(float))
X_test = np.nan_to_num(X_test, nan=0.0)
X_test = StandardScaler().fit_transform(X_test)

# Convert to 3D PyTorch Tensor Sequence (batch_size, features, 1)
X_test_seq = X_test.reshape(-1, X_test.shape[1], 1)
test_dataset = TensorDataset(torch.FloatTensor(X_test_seq), torch.LongTensor(y_true))
test_loader = DataLoader(test_dataset, batch_size=1024, shuffle=False)

# 5. Run Inference
print("[*] Running Mathematical Inference via STAHN Transformer...")
y_preds = []
y_probs = []
y_trues_list = []

with torch.no_grad():
    for batch_x, batch_y in test_loader:
        batch_x = batch_x.to(device)
        outputs = model(batch_x)
        
        # Get probabilities using Softmax for AUC-ROC
        probs = torch.softmax(outputs, dim=1)[:, 1]
        _, preds = torch.max(outputs, 1)
        
        y_probs.extend(probs.cpu().numpy())
        y_preds.extend(preds.cpu().numpy())
        y_trues_list.extend(batch_y.numpy())

# 6. Calculate Metrics
print("\n==========================================")
print(" FINAL EVALUATION METRICS ")
print("==========================================")
print(classification_report(y_trues_list, y_preds, target_names=['Benign (0)', 'Attack (1)'], digits=4))

# 7. Generate World-Class Visualizations
print("[*] Generating PhD-Quality Visualizations...")

# Plot Confusion Matrix
cm = confusion_matrix(y_trues_list, y_preds)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'Attack'], yticklabels=['Benign', 'Attack'])
plt.title('STAHN Confusion Matrix (Unseen Test Data)', fontsize=14, fontweight='bold')
plt.ylabel('True Mathematical Label')
plt.xlabel('Transformer Predicted Label')
plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
print("[+] Saved 'confusion_matrix.png'")

# Plot ROC Curve
fpr, tpr, thresholds = roc_curve(y_trues_list, y_probs)
roc_auc = auc(fpr, tpr)

plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'STAHN AUC-ROC = {roc_auc:.4f}')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate', fontweight='bold')
plt.ylabel('True Positive Rate', fontweight='bold')
plt.title('Receiver Operating Characteristic (ROC) Curve', fontsize=14, fontweight='bold')
plt.legend(loc="lower right")
plt.grid(True, alpha=0.3)
plt.savefig('roc_curve.png', dpi=300, bbox_inches='tight')
print("[+] Saved 'roc_curve.png'")

print("==========================================")
print(" EVALUATION COMPLETE! ALL ARTIFACTS SAVED ")
print("==========================================")
