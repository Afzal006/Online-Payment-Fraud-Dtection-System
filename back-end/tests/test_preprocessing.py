import pandas as pd
import numpy as np
import pytest

from ml.preprocessing import (
    prepare_features_and_target,
    split_data,
    build_preprocessor,
    get_transformed_feature_names,
    EXCLUDED_COLUMNS,
    TRANSACTION_TYPES,
)


@pytest.fixture
def mock_dataset():
    """Create a small representative DataFrame."""
    rows = []
    for i in range(100):
        is_fraud = 1 if i < 10 else 0
        rows.append({
            "step": i + 1,
            "type": TRANSACTION_TYPES[i % len(TRANSACTION_TYPES)],
            "amount": float(100.0 * (i + 1)),
            "nameOrig": f"C{i:06d}",
            "oldbalanceOrg": float(5000.0),
            "newbalanceOrig": float(5000.0 - (100.0 * (i + 1)) if is_fraud == 0 else 0.0),
            "nameDest": f"M{i:06d}" if i % 2 == 0 else f"C{i:06d}",
            "oldbalanceDest": float(0.0),
            "newbalanceDest": float(100.0 * (i + 1)),
            "isFraud": is_fraud,
            "isFlaggedFraud": 1 if i == 0 else 0,
        })
    return pd.DataFrame(rows)


def test_target_separation_and_leakage_exclusion(mock_dataset):
    """Verify target separation and that excluded columns are never in X."""
    X, y = prepare_features_and_target(mock_dataset, temporal_option="hourOfDay")

    # Target checks
    assert len(y) == len(mock_dataset)
    assert y.name == "isFraud"
    assert "isFraud" not in X.columns

    # Leakage exclusion checks
    for col in EXCLUDED_COLUMNS:
        assert col not in X.columns, f"Excluded column '{col}' leaked into feature matrix X"

    # Ensure 11 logical features present
    assert len(X.columns) == 11


def test_stratified_split_preserves_balance(mock_dataset):
    """Verify train/test splitting maintains stratified target ratio."""
    X, y = prepare_features_and_target(mock_dataset)
    X_train, X_test, y_train, y_test = split_data(X, y, test_size=0.20, random_state=42)

    assert len(X_train) == 80
    assert len(X_test) == 20
    assert y_train.sum() == 8  # 10% fraud preserved
    assert y_test.sum() == 2   # 10% fraud preserved


def test_column_transformer_structure(mock_dataset):
    """Verify ColumnTransformer outputs exactly 15 numerical features."""
    X, y = prepare_features_and_target(mock_dataset)
    num_cols = [c for c in X.columns if c != "type"]

    preprocessor = build_preprocessor(
        categorical_features=["type"],
        numerical_features=num_cols,
        scale_numeric=False,
    )
    X_transformed = preprocessor.fit_transform(X)

    # 5 one-hot columns (CASH_OUT, TRANSFER, PAYMENT, CASH_IN, DEBIT) + 10 numerical = 15 columns
    assert X_transformed.shape[1] == 15
    feature_names = get_transformed_feature_names(preprocessor, numerical_features=num_cols)
    assert len(feature_names) == 15
