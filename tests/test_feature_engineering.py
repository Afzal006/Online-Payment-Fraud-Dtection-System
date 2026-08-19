import pandas as pd
import numpy as np
import pytest

from ml.feature_engineering import (
    compute_error_balance_orig,
    compute_error_balance_dest,
    compute_amount_to_balance_ratio,
    compute_hour_of_day,
    compute_is_merchant_dest,
    engineer_features,
    get_model_feature_names,
)


def test_balance_error_formulas():
    """Verify exact calculation of sender and recipient balance discrepancies."""
    # Consistent sender balance: 1000 - 200 = 800 -> error 0
    assert compute_error_balance_orig(1000.0, 200.0, 800.0) == 0.0
    # Inconsistent sender balance (e.g. drained to 0): 1000 - 200 - 0 = 800
    assert compute_error_balance_orig(1000.0, 200.0, 0.0) == 800.0

    # Consistent receiver balance: 500 + 200 = 700 -> error 0
    assert compute_error_balance_dest(500.0, 200.0, 700.0) == 0.0
    # Inconsistent receiver balance: 500 + 200 - 0 = 700
    assert compute_error_balance_dest(500.0, 200.0, 0.0) == 700.0


def test_amount_to_balance_ratio_zero_division_safety():
    """Verify that amountToBalanceRatio is safe when sender balance is zero."""
    ratio_zero_balance = compute_amount_to_balance_ratio(500.0, 0.0)
    assert not np.isnan(ratio_zero_balance)
    assert not np.isinf(ratio_zero_balance)
    assert ratio_zero_balance == 500.0 / 1.0

    # Large balance
    ratio_large = compute_amount_to_balance_ratio(100.0, 999.0)
    assert round(ratio_large, 3) == 0.100


def test_hour_of_day_calculation():
    """Verify diurnal hour extraction: step % 24."""
    assert compute_hour_of_day(1) == 1
    assert compute_hour_of_day(24) == 0
    assert compute_hour_of_day(25) == 1
    assert compute_hour_of_day(743) == 743 % 24


def test_merchant_destination_detection():
    """Verify binary detection of merchant accounts ('M...')."""
    assert compute_is_merchant_dest("M123456789") == 1
    assert compute_is_merchant_dest("C987654321") == 0
    assert compute_is_merchant_dest("") == 0


def test_engineer_features_pipeline():
    """Verify DataFrame-level feature engineering."""
    df_sample = pd.DataFrame([{
        "step": 15,
        "type": "TRANSFER",
        "amount": 250000.0,
        "nameOrig": "C111111",
        "oldbalanceOrg": 250000.0,
        "newbalanceOrig": 0.0,
        "nameDest": "C222222",
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
    }])

    df_out = engineer_features(df_sample, temporal_option="hourOfDay")

    assert "errorBalanceOrig" in df_out.columns
    assert "errorBalanceDest" in df_out.columns
    assert "amountToBalanceRatio" in df_out.columns
    assert "hourOfDay" in df_out.columns
    assert "isMerchantDest" in df_out.columns

    assert df_out["hourOfDay"].iloc[0] == 15
    assert df_out["isMerchantDest"].iloc[0] == 0
    assert df_out["errorBalanceOrig"].iloc[0] == 0.0
    assert df_out["errorBalanceDest"].iloc[0] == 250000.0


def test_engineer_features_missing_column_error():
    """Verify error raised when essential columns are missing."""
    df_invalid = pd.DataFrame([{"amount": 100.0}])
    with pytest.raises(KeyError):
        engineer_features(df_invalid)
