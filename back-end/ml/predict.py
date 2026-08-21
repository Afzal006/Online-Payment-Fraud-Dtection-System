"""
Real-Time Inference Interface for Online Payment Fraud Detection.

Provides a clean, standalone inference function that accepts a raw transaction dictionary
or DataFrame, applies domain feature engineering, and generates a fraud probability
and predicted class using the approved production model artifact (model.joblib).
"""

import sys
from pathlib import Path
from typing import Dict, Any, Union, Optional
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ml.inference import FraudInferenceService, get_inference_service, predict_single_transaction

# Backwards compatible alias
FraudPredictor = FraudInferenceService


def predict(transaction: Dict[str, Any], model_path: Optional[str] = None) -> Dict[str, Any]:
    """Top-level functional interface for single transaction prediction."""
    if model_path:
        service = FraudInferenceService(model_path=model_path)
        return service.predict_transaction(transaction)
    return predict_single_transaction(transaction)
