import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base application configuration."""

    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-fraud-detection-2026")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret-key-fraud-detection-2026")
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 24 hours in seconds

    # Database configuration
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_NAME = os.getenv("DB_NAME", "fraud_detection")
    DB_USER = os.getenv("DB_USER", "fraud_app_user")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "change-me")

    # MySQL database URI with fallback to SQLite for local development / testing if MySQL is unavailable
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ML Artifact Paths
    MODEL_ARTIFACT_PATH = os.getenv("MODEL_ARTIFACT_PATH", str(BASE_DIR / "ml" / "artifacts" / "model.joblib"))
    PREPROCESSOR_ARTIFACT_PATH = os.getenv(
        "PREPROCESSOR_ARTIFACT_PATH", str(BASE_DIR / "ml" / "artifacts" / "preprocessor.joblib")
    )
    FEATURE_NAMES_PATH = os.getenv(
        "FEATURE_NAMES_PATH", str(BASE_DIR / "ml" / "artifacts" / "feature_names.json")
    )

    # Risk Scoring Policy & Thresholds (Supplement Section 4)
    RISK_LOW_MAX = int(os.getenv("RISK_LOW_MAX", "30"))        # 0 - 30: LOW (Approve immediately)
    RISK_MEDIUM_MAX = int(os.getenv("RISK_MEDIUM_MAX", "70"))    # 31 - 70: MEDIUM (Trigger OTP)
    # 71 - 100: HIGH (Fraud alert + OTP + review)

    # OTP Verification Settings (Supplement Section 6.1)
    OTP_EXPIRY_SECONDS = int(os.getenv("OTP_EXPIRY_SECONDS", "180"))  # 3 minutes
    OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "3"))

    # Password Reset Settings (Phase 2.5)
    PASSWORD_RESET_TOKEN_EXPIRY_MINUTES = int(os.getenv("PASSWORD_RESET_TOKEN_EXPIRY_MINUTES", "10"))
    PASSWORD_RESET_MAX_REQUESTS_PER_WINDOW = int(os.getenv("PASSWORD_RESET_MAX_REQUESTS_PER_WINDOW", "3"))
    PASSWORD_RESET_REQUEST_WINDOW_MINUTES = int(os.getenv("PASSWORD_RESET_REQUEST_WINDOW_MINUTES", "15"))
    PASSWORD_RESET_MAX_ATTEMPTS = int(os.getenv("PASSWORD_RESET_MAX_ATTEMPTS", "5"))
    PASSWORD_RESET_DEV_MODE = os.getenv("PASSWORD_RESET_DEV_MODE", "true").lower() in ["true", "1", "yes"]


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False
    PASSWORD_RESET_DEV_MODE = True


class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    JWT_SECRET_KEY = "test-jwt-secret-key-32-byte-length-secure-2026!"
    PASSWORD_RESET_DEV_MODE = True


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    PASSWORD_RESET_DEV_MODE = False


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
