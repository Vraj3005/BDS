"""
Convenience Root Entrypoint -- Cyber Threat Intelligence Platform
Usage:
    python run_platform.py              # Full terminal demonstration
    python run_platform.py --quick      # Fast demonstration
    python run_platform.py --dashboard  # Launch Streamlit web dashboard
    python run_platform.py --test       # Run End-to-End Test Suite
    python run_platform.py --ip <IP>    # Lookup specific threat IP
"""

import sys
from pathlib import Path
import subprocess

if __name__ == "__main__":
    demo_script = Path(__file__).resolve().parent / "spark" / "jobs" / "run_demo.py"
    cmd = [sys.executable, str(demo_script)] + sys.argv[1:]
    sys.exit(subprocess.run(cmd).returncode)
