#!/usr/bin/env python
"""
Direct CLI Diagnostic Tool for FraudShield AI SMTP Email Delivery.

Usage:
    python scripts/test_smtp.py <recipient-email>
"""

import os
import sys
from pathlib import Path

# Ensure backend root directory is in sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from test_smtp_cli import main

if __name__ == "__main__":
    main()
