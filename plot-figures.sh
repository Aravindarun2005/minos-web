#!/usr/bin/env bash
# Draws Figures 2-5 like the paper from benchmark-results/*.csv (needs Python 3 + matplotlib).
cd "$(dirname "$0")"
python3 -c "import matplotlib" 2>/dev/null || python3 -m pip install matplotlib
python3 plot_figures.py "$@"
