@echo off
title STAHN Interactive Intrusion Detection
color 0A
echo =======================================================
echo  STAHN: Squeeze-and-Excitation Temporal Attention
echo =======================================================
echo Checking and installing Python dependencies...
python -m pip install torch pandas numpy scikit-learn --quiet

echo Launching Interactive CLI...
python interactive_inference.py

echo.
pause
