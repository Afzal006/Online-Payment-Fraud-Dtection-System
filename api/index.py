import os
import sys
from pathlib import Path

# Add backend directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "back-end"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import create_app
from database.init_db import init_database

env_name = os.getenv("FLASK_ENV", "production")
app = create_app(env_name)

try:
    init_database(app)
except Exception as e:
    app.logger.warning(f"Database init notice: {e}")

# Vercel WSGI entrypoint
# The variable 'app' is automatically picked up by @vercel/python
