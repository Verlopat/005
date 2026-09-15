import os

print("🔧 Fixing stahn_architecture.py for safe importing...")

with open('stahn_architecture.py', 'r') as f:
    content = f.read()

# 1. Prevent the dataset check from exiting
content = content.replace(
    'if not csv_files:',
    'if not csv_files and "dataset_ciciot2023" in DATASET_DIR:\n        print("WARNING: Dataset folder empty - running in import mode")\n        csv_files = []'
)

# 2. Disable the main training block
content = content.replace(
    'if __name__ == "__main__":',
    '# === TRAINING BLOCK DISABLED FOR IMPORT ===\nif False and __name__ == "__main__":'
)

with open('stahn_architecture.py', 'w') as f:
    f.write(content)

print("✅ Fix applied successfully!")
print("You can now safely import STAHN from other folders.")
