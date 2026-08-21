import os
from pathlib import Path
import pytest
from app import create_app
from app.config import Config, DevelopmentConfig, TestingConfig, ProductionConfig


def test_required_packages_imported():
    """Verify that all core project dependencies can be imported successfully."""
    import flask
    import flask_cors
    import flask_jwt_extended
    import flask_sqlalchemy
    import pymysql
    import pandas
    import numpy
    import sklearn
    import xgboost
    import shap
    import imblearn
    import joblib
    import dotenv

    assert flask.__name__ == "flask"
    assert pandas.__name__ == "pandas"
    assert numpy.__name__ == "numpy"
    assert sklearn.__name__ == "sklearn"
    assert xgboost.__name__ == "xgboost"
    assert shap.__name__ == "shap"
    assert imblearn.__name__ == "imblearn"
    assert joblib.__name__ == "joblib"
    assert dotenv.__name__ == "dotenv"


def test_directory_structure_exists():
    """Verify that all specified project directories exist."""
    base_dir = Path(__file__).resolve().parent.parent  # back-end
    root_dir = base_dir.parent                        # project root
    frontend_dir = root_dir / "front-end"

    expected_dirs = [
        base_dir / "app",
        base_dir / "app" / "routes",
        base_dir / "app" / "services",
        base_dir / "app" / "models",
        base_dir / "app" / "utils",
        base_dir / "ml",
        base_dir / "ml" / "artifacts",
        base_dir / "ml" / "notebooks",
        base_dir / "dataset",
        base_dir / "database",
        base_dir / "tests",
        base_dir / "docs",
        frontend_dir / "templates",
        frontend_dir / "static",
    ]
    for directory in expected_dirs:
        assert directory.exists(), f"Directory {directory} does not exist"
        assert directory.is_dir(), f"Path {directory} is not a directory"


def test_config_defaults():
    """Verify that configuration settings match Supplement specifications."""
    assert Config.RISK_LOW_MAX == 30
    assert Config.RISK_MEDIUM_MAX == 70
    assert Config.OTP_EXPIRY_SECONDS == 180
    assert Config.OTP_MAX_ATTEMPTS == 3
    assert TestingConfig.TESTING is True


def test_app_factory_and_health_endpoint():
    """Verify application creation and health check endpoint."""
    app = create_app("testing")
    client = app.test_client()

    response = client.get("/api/health")
    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "healthy"
    assert "Online Payment Fraud Detection" in data["project"]
    assert data["version"] == "1.0.0"


def test_environment_files_exist():
    """Verify that .env.example, requirements.txt, and setup files are present."""
    base_dir = Path(__file__).resolve().parent.parent
    root_dir = base_dir.parent
    assert (base_dir / ".env.example").exists() or (root_dir / ".env.example").exists()
    assert (base_dir / "requirements.txt").exists()
    assert (base_dir / ".gitignore").exists() or (root_dir / ".gitignore").exists()
    assert (base_dir / "run.py").exists()
    assert (base_dir / "DATASET_SETUP.md").exists()


def test_dataset_check_reports_status_gracefully():
    """Verify dataset existence checker runs and reports clear status without crashing."""
    from ml.check_dataset import find_dataset_file, DATASET_DIR

    is_present, path, message = find_dataset_file()
    assert isinstance(is_present, bool)
    assert isinstance(message, str)
    assert len(message) > 0
    # When dataset is not present, path is None and informative message is returned
    if not is_present:
        assert path is None
        assert "dataset" in message.lower()

