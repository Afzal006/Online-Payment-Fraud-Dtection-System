import os
from app import create_app
from database.init_db import init_database

env_name = os.getenv("FLASK_ENV", "development")
app = create_app(env_name)

if __name__ == "__main__":
    init_database(app)
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=(env_name == "development"))
