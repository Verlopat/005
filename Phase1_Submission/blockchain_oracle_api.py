import torch
import torch.nn as nn
from flask import Flask, request, jsonify
import numpy as np

# ==========================================
# PHASE 2: BLOCKCHAIN ORACLE API BRIDGE
# ==========================================
# This script bridges the ML model to the Blockchain.
# Smart Contracts (Hyperledger/Ethereum) cannot run PyTorch.
# They must use an Oracle to send HTTP requests to this API.
# This API runs the ML inference and returns the result to the chain.

app = Flask(__name__)

# Rebuild the mathematical architecture to load the weights
class STAHN(nn.Module):
    def __init__(self, input_size=1, num_classes=2):
        super(STAHN, self).__init__()
        self.conv1 = nn.Conv1d(in_channels=input_size, out_channels=64, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3, padding=1)
        self.pool1 = nn.MaxPool1d(kernel_size=2)
        self.pool2 = nn.MaxPool1d(kernel_size=2)
        encoder_layer = nn.TransformerEncoderLayer(d_model=128, nhead=8, dim_feedforward=256, dropout=0.2, batch_first=True)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=2)
        self.lstm = nn.LSTM(input_size=128, hidden_size=256, num_layers=2, batch_first=True, bidirectional=True)
        self.fc1 = nn.Linear(256 * 2, 128)
        self.fc2 = nn.Linear(128, num_classes)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        x = x.permute(0, 2, 1)
        x = torch.relu(self.conv1(x))
        x = self.pool1(x)
        x = torch.relu(self.conv2(x))
        x = self.pool2(x)
        x = x.permute(0, 2, 1)
        x = self.transformer(x)
        lstm_out, _ = self.lstm(x)
        final_state = lstm_out[:, -1, :]
        out = torch.relu(self.fc1(final_state))
        out = self.dropout(out)
        out = self.fc2(out)
        return out

# Load the World Record Weights into Memory
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = STAHN().to(device)
model.load_state_dict(torch.load('stahn_model.pth', map_location=device))
model.eval()

print("[*] Blockchain Oracle Bridge is ACTIVE. Listening for Smart Contract queries...")

@app.route('/verify_transaction', methods=['POST'])
def verify_transaction():
    try:
        data = request.json
        features = data.get('features', [])
        
        if len(features) != 46:
            return jsonify({"error": "Exactly 46 network features required."}), 400
            
        # Convert JSON payload into mathematical tensor
        tensor_input = torch.FloatTensor([features]).unsqueeze(2).to(device)
        
        with torch.no_grad():
            outputs = model(tensor_input)
            probs = torch.softmax(outputs, dim=1)[:, 1].item()
            prediction = int(torch.argmax(outputs, dim=1).item())
            
        # Format response for the Blockchain Smart Contract
        return jsonify({
            "is_attack": bool(prediction == 1),
            "confidence_score": round(probs, 4),
            "action_required": "ISOLATE_NODE" if prediction == 1 else "ALLOW_TRAFFIC",
            "model_version": "stahn_v1_98.62_acc"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Run API on port 5000 so the Blockchain Oracle can hit it
    app.run(host='0.0.0.0', port=5000)
