import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the backend
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file (supports back-end/.env and root/.env)
if (BASE_DIR / ".env").exists():
    load_dotenv(BASE_DIR / ".env")
elif (BASE_DIR.parent / ".env").exists():
    load_dotenv(BASE_DIR.parent / ".env")
else:
    load_dotenv()


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

    # Database URI with postgresql scheme normalization and explicit DATABASE_URL support
    raw_db_url = os.getenv("DATABASE_URL")
    if raw_db_url and raw_db_url.strip():
        clean_url = raw_db_url.strip()
        if clean_url.startswith("postgres://"):
            clean_url = clean_url.replace("postgres://", "postgresql://", 1)
        SQLALCHEMY_DATABASE_URI = clean_url
    else:
        SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
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
    PASSWORD_RESET_TOKEN_EXPIRY_MINUTES = int(os.getenv("PASSWORD_RESET_TOKEN_EXPIRY_MINUTES", "15"))
    PASSWORD_RESET_MAX_REQUESTS_PER_WINDOW = int(os.getenv("PASSWORD_RESET_MAX_REQUESTS_PER_WINDOW", "3"))
    PASSWORD_RESET_REQUEST_WINDOW_MINUTES = int(os.getenv("PASSWORD_RESET_REQUEST_WINDOW_MINUTES", "15"))
    PASSWORD_RESET_MAX_ATTEMPTS = int(os.getenv("PASSWORD_RESET_MAX_ATTEMPTS", "5"))
    PASSWORD_RESET_DEV_MODE = os.getenv("PASSWORD_RESET_DEV_MODE", "false").lower() in ["true", "1", "yes"]

    # Email & SMTP Delivery Configuration (Phase 5 & 7.1)
    MAIL_PROVIDER = os.getenv("MAIL_PROVIDER", os.getenv("EMAIL_PROVIDER", "development"))
    SMTP_HOST = os.getenv("MAIL_SERVER", os.getenv("SMTP_HOST", os.getenv("SMTP_SERVER", "")))
    SMTP_PORT = int(os.getenv("MAIL_PORT", os.getenv("SMTP_PORT", "587")))
    SMTP_USERNAME = os.getenv("MAIL_USERNAME", os.getenv("SMTP_USERNAME", os.getenv("SMTP_USER", "")))
    SMTP_PASSWORD = os.getenv("MAIL_PASSWORD", os.getenv("SMTP_PASSWORD", ""))
    
    # SSL vs TLS support
    raw_tls = os.getenv("MAIL_USE_TLS", os.getenv("SMTP_USE_TLS", "true"))
    SMTP_USE_TLS = str(raw_tls).lower() in ["true", "1", "yes"]
    raw_ssl = os.getenv("MAIL_USE_SSL", os.getenv("SMTP_USE_SSL", "false"))
    SMTP_USE_SSL = str(raw_ssl).lower() in ["true", "1", "yes"]

    SMTP_FROM_EMAIL = os.getenv("MAIL_DEFAULT_SENDER", os.getenv("SMTP_FROM_EMAIL", os.getenv("EMAIL_FROM", "security@fraudshield.ai")))
    SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "FraudShield AI Security")
    APP_PUBLIC_URL = os.getenv("APP_PUBLIC_URL", "")

    # SMS Gateway Configuration
    SMS_PROVIDER = os.getenv("SMS_PROVIDER", "development")
    MSG91_AUTH_KEY = os.getenv("MSG91_AUTH_KEY", "")
    MSG91_TEMPLATE_ID = os.getenv("MSG91_TEMPLATE_ID", "")
    MSG91_SENDER_ID = os.getenv("MSG91_SENDER_ID", "FRDSHD")


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
    MAIL_PROVIDER = "development"
    EMAIL_PROVIDER = "development"


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    PASSWORD_RESET_DEV_MODE = False


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
