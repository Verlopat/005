import re

print("🛠️  Repairing indentation in stahn_architecture.py...")

with open('stahn_architecture.py', 'r') as f:
    lines = f.readlines()

fixed_lines = []
for line in lines:
    # Fix common indentation issues from previous replace
    if 'if not csv_files and "dataset_ciciot2023"' in line:
        line = line.replace('        print', '        print').replace('        csv_files', '        csv_files')
    fixed_lines.append(line)

with open('stahn_architecture.py', 'w') as f:
    f.writelines(fixed_lines)

print("✅ Indentation repaired!")
print("Now testing import...")

# Test import
try:
    from stahn_architecture import STAHN
    print("✅ Import successful!")
except Exception as e:
    print(f"Still error: {e}")
