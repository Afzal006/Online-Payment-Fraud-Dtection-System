import os
import sys
from pathlib import Path

# Ensure backend root directory is in sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import create_app
from database.init_db import init_database

env_name = os.getenv("FLASK_ENV", "development")
app = create_app(env_name)

# Ensure database tables and schema are initialized for WSGI (Gunicorn) & CLI
try:
    init_database(app)
except Exception as e:
    app.logger.warning(f"Database initialization warning on startup: {e}")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=(env_name == "development"))
