"""
ML Preprocessing Pipeline for Online Payment Fraud Detection.

This module handles dataset loading, stratified splitting, and sklearn ColumnTransformer
construction to encode categorical features and scale numeric features where needed.
"""

from pathlib import Path
from typing import Tuple, List, Optional, Dict, Any
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline

from ml.check_dataset import find_dataset_file
from ml.feature_engineering import engineer_features, get_model_feature_names

# Known transaction categories in PaySim
TRANSACTION_TYPES = ["CASH_OUT", "TRANSFER", "PAYMENT", "CASH_IN", "DEBIT"]

# Columns strictly excluded from model feature matrix
EXCLUDED_COLUMNS = ["isFraud", "isFlaggedFraud", "nameOrig", "nameDest"]


def load_dataset(
    sample_frac: Optional[float] = None,
    random_state: int = 42,
    chunksize: int = 500_000,
) -> pd.DataFrame:
    """
    Load the PaySim dataset CSV from dataset/ directory in memory-efficient chunks.

    Parameters:
        sample_frac: If set (e.g. 0.1 for 10%), returns a stratified sample of rows.
                     If None, loads all 6.36 million rows using optimized dtypes.
        random_state: Random seed for sampling reproducibility.
        chunksize: Size of chunks to read from disk.

    Returns:
        pd.DataFrame containing the raw transaction dataset.
    """
    is_present, csv_path, message = find_dataset_file()
    if not is_present or csv_path is None:
        raise FileNotFoundError(f"Dataset not available: {message}")

    dtypes = {
        "step": "int32",
        "type": "category",
        "amount": "float32",
        "nameOrig": "object",
        "oldbalanceOrg": "float32",
        "newbalanceOrig": "float32",
        "nameDest": "object",
        "oldbalanceDest": "float32",
        "newbalanceDest": "float32",
        "isFraud": "int8",
        "isFlaggedFraud": "int8",
    }

    if sample_frac is None or sample_frac >= 1.0:
        # Load all records with memory-optimized dtypes
        df = pd.read_csv(csv_path, dtype=dtypes)
        return df
    else:
        # Chunked sampling to keep memory footprint minimal
        sampled_chunks = []
        for chunk in pd.read_csv(csv_path, dtype=dtypes, chunksize=chunksize):
            chunk_sample = chunk.sample(frac=sample_frac, random_state=random_state)
            sampled_chunks.append(chunk_sample)
        return pd.concat(sampled_chunks, ignore_index=True)


def prepare_features_and_target(
    df: pd.DataFrame,
    temporal_option: str = "hourOfDay",
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Apply feature engineering and separate model features (X) and target (y).

    Ensures that isFraud, isFlaggedFraud, nameOrig, and nameDest are removed from X.

    Parameters:
        df: Raw DataFrame containing PaySim columns.
        temporal_option: 'hourOfDay' (Option A), 'step' (Option B), or 'both' (Option C).

    Returns:
        (X, y) tuple where X contains only model features and y is the binary target series.
    """
    if "isFraud" not in df.columns:
        raise KeyError("Target variable 'isFraud' is missing from DataFrame.")

    # Target series
    y = df["isFraud"].copy()

    # Engineer domain features
    df_engineered = engineer_features(df, temporal_option=temporal_option, copy=True)

    # Select only the approved model feature columns
    feature_cols = get_model_feature_names(temporal_option=temporal_option)
    X = df_engineered[feature_cols].copy()

    return X, y


def split_data(
    X: pd.DataFrame,
    y: pd.Series,
    test_size: float = 0.20,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Perform stratified train/test split.

    Parameters:
        X: Feature matrix.
        y: Target series.
        test_size: Proportion of test set (default 0.20 = 20%).
        random_state: Random seed for reproducibility.

    Returns:
        (X_train, X_test, y_train, y_test)
    """
    return train_test_split(
        X,
        y,
        test_size=test_size,
        stratify=y,
        random_state=random_state,
    )


def build_preprocessor(
    categorical_features: List[str] = ["type"],
    numerical_features: Optional[List[str]] = None,
    scale_numeric: bool = False,
) -> ColumnTransformer:
    """
    Construct a scikit-learn ColumnTransformer for categorical one-hot encoding
    and optional numerical scaling.

    Parameters:
        categorical_features: List of categorical feature names.
        numerical_features: List of numerical feature names.
        scale_numeric: If True, uses StandardScaler for numerical features (useful for Logistic Regression).
                       If False, passes numerical features through unchanged (ideal for tree models).

    Returns:
        ColumnTransformer instance.
    """
    transformers = [
        (
            "cat",
            OneHotEncoder(
                categories=[TRANSACTION_TYPES],
                handle_unknown="ignore",
                sparse_output=False,
            ),
            categorical_features,
        )
    ]

    if numerical_features is not None:
        if scale_numeric:
            transformers.append(("num", StandardScaler(), numerical_features))
        else:
            transformers.append(("num", "passthrough", numerical_features))

    preprocessor = ColumnTransformer(
        transformers=transformers,
        remainder="passthrough",
    )
    return preprocessor


def get_transformed_feature_names(
    preprocessor: ColumnTransformer,
    categorical_features: List[str] = ["type"],
    numerical_features: Optional[List[str]] = None,
) -> List[str]:
    """
    Extract the output column names generated by the ColumnTransformer.
    """
    try:
        return list(preprocessor.get_feature_names_out())
    except Exception:
        # Fallback manual reconstruction if not yet fitted
        cat_names = [f"type_{t}" for t in TRANSACTION_TYPES]
        num_names = numerical_features or []
        return cat_names + num_names
