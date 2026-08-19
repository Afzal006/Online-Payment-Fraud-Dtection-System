"""
Feature Engineering Module for Online Payment Fraud Detection.

This module implements domain-specific feature transformations for the PaySim
financial transaction dataset.

Logical Features:
1. errorBalanceOrig: Inconsistency in sender balance after transaction.
2. errorBalanceDest: Inconsistency in recipient balance after transaction.
3. amountToBalanceRatio: Fraction of sender balance being transferred (account draining).
4. hourOfDay: Diurnal 24-hour cycle representation (step % 24).
5. isMerchantDest: Binary flag indicating if recipient is a merchant account ('M...').

Production / Real-Time Availability Note:
- errorBalanceOrig, hourOfDay, isMerchantDest, amountToBalanceRatio are computable
  pre-authorization.
- errorBalanceDest relies on recipient balances, which in external inter-bank
  scenarios may not be available pre-authorization.
"""

from typing import Union, Dict, Any, List
import pandas as pd
import numpy as np


def compute_error_balance_orig(
    oldbalance_org: Union[float, pd.Series, np.ndarray],
    amount: Union[float, pd.Series, np.ndarray],
    newbalance_orig: Union[float, pd.Series, np.ndarray],
) -> Union[float, pd.Series, np.ndarray]:
    """
    Compute sender balance discrepancy: oldbalanceOrg - amount - newbalanceOrig.
    A non-zero value indicates an inconsistent sender balance state.
    """
    return oldbalance_org - amount - newbalance_orig


def compute_error_balance_dest(
    oldbalance_dest: Union[float, pd.Series, np.ndarray],
    amount: Union[float, pd.Series, np.ndarray],
    newbalance_dest: Union[float, pd.Series, np.ndarray],
) -> Union[float, pd.Series, np.ndarray]:
    """
    Compute recipient balance discrepancy: oldbalanceDest + amount - newbalanceDest.
    A non-zero value indicates an inconsistent destination balance state.
    """
    return oldbalance_dest + amount - newbalance_dest


def compute_amount_to_balance_ratio(
    amount: Union[float, pd.Series, np.ndarray],
    oldbalance_org: Union[float, pd.Series, np.ndarray],
) -> Union[float, pd.Series, np.ndarray]:
    """
    Compute ratio of transaction amount to sender's initial balance.
    Uses +1.0 in denominator for numerical stability and zero-division prevention.
    A high ratio close to or exceeding 1.0 indicates an attempt to drain the account.
    """
    return amount / (oldbalance_org + 1.0)


def compute_hour_of_day(
    step: Union[int, pd.Series, np.ndarray],
) -> Union[int, pd.Series, np.ndarray]:
    """
    Compute 24-hour diurnal cycle time bucket: step % 24.
    In PaySim, 1 step = 1 hour.
    """
    return step % 24


def compute_is_merchant_dest(
    name_dest: Union[str, pd.Series],
) -> Union[int, pd.Series]:
    """
    Determine if recipient is a merchant account (starts with 'M').
    Returns 1 for merchant, 0 for customer ('C').
    """
    if isinstance(name_dest, pd.Series):
        return name_dest.astype(str).str.startswith("M").astype(int)
    elif isinstance(name_dest, str):
        return 1 if name_dest.startswith("M") else 0
    else:
        return 0


def engineer_features(
    df: pd.DataFrame,
    temporal_option: str = "hourOfDay",
    copy: bool = True,
) -> pd.DataFrame:
    """
    Apply full feature engineering pipeline to a pandas DataFrame.

    Parameters:
        df: Input DataFrame with raw PaySim columns.
        temporal_option: 'hourOfDay' (Option A), 'step' (Option B), or 'both' (Option C).
        copy: Whether to create a copy of the input DataFrame.

    Returns:
        DataFrame with engineered features added.
    """
    data = df.copy() if copy else df

    # Validate essential source columns
    required_cols = [
        "amount",
        "oldbalanceOrg",
        "newbalanceOrig",
        "oldbalanceDest",
        "newbalanceDest",
    ]
    for col in required_cols:
        if col not in data.columns:
            raise KeyError(f"Required column '{col}' missing for feature engineering.")

    # 1. Sender balance discrepancy
    data["errorBalanceOrig"] = compute_error_balance_orig(
        data["oldbalanceOrg"], data["amount"], data["newbalanceOrig"]
    )

    # 2. Recipient balance discrepancy
    data["errorBalanceDest"] = compute_error_balance_dest(
        data["oldbalanceDest"], data["amount"], data["newbalanceDest"]
    )

    # 3. Amount to sender balance ratio
    data["amountToBalanceRatio"] = compute_amount_to_balance_ratio(
        data["amount"], data["oldbalanceOrg"]
    )

    # 4. Temporal feature
    if "step" in data.columns:
        data["hourOfDay"] = compute_hour_of_day(data["step"])
    elif "hourOfDay" not in data.columns:
        data["hourOfDay"] = 0

    # 5. Merchant recipient flag
    if "nameDest" in data.columns:
        data["isMerchantDest"] = compute_is_merchant_dest(data["nameDest"])
    elif "isMerchantDest" not in data.columns:
        data["isMerchantDest"] = 0

    return data


def get_model_feature_names(temporal_option: str = "hourOfDay") -> List[str]:
    """
    Return the list of logical feature column names expected by the model pipeline.
    """
    base_features = [
        "type",
        "amount",
        "oldbalanceOrg",
        "newbalanceOrig",
        "oldbalanceDest",
        "newbalanceDest",
        "errorBalanceOrig",
        "errorBalanceDest",
        "isMerchantDest",
        "amountToBalanceRatio",
    ]

    if temporal_option == "hourOfDay":
        return base_features + ["hourOfDay"]
    elif temporal_option == "step":
        return base_features + ["step"]
    elif temporal_option == "both":
        return base_features + ["step", "hourOfDay"]
    else:
        return base_features + ["hourOfDay"]
