import os
import sys

# Add src to path when running this script directly.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core import activate_sentinel, set_approval_handler
from src.approval import tkinter_approval_handler

activate_sentinel()
set_approval_handler(tkinter_approval_handler)

# This path is outside allowed workspace, so it triggers approval flow.
try:
    with open("/tmp/sentinel-approval-test.txt", "w") as f:
        f.write("test")
    print("approved: write completed")
except Exception as e:
    print(f"rejected: {e}")
