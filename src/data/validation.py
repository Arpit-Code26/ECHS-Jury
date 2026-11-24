"""
Data Validation Module for CyberSentinel.
Ensures incoming datasets conform to expected feature schemas,
guards against corrupted rows, and provides actionable error reports.
"""
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd
from config.model_config import CANONICAL_FEATURES, TARGET_COLUMN

def validate_dataset_schema(
    df: pd.DataFrame,
    expected_features: Optional[List[str]] = None,
    require_label: bool = False
) -> Dict[str, Any]:
    """
    Validates that a DataFrame contains the expected features and structure.
    Returns a detailed validation report.
    """
    if expected_features is None:
        expected_features = CANONICAL_FEATURES

    # Clean column names (strip whitespace)
    normalized_cols = [c.strip() for c in df.columns]
    col_mapping = {orig: orig.strip() for orig in df.columns}
    
    # Check for target column
    has_target = any(c.lower() == TARGET_COLUMN.lower() for c in normalized_cols)
    
    # Check matching, missing, and extra features
    normalized_set = set(normalized_cols)
    expected_set = set(expected_features)
    
    matched_features = [f for f in expected_features if f in normalized_set]
    missing_features = [f for f in expected_features if f not in normalized_set]
    extra_features = [c for c in normalized_cols if c not in expected_set and c.lower() != TARGET_COLUMN.lower()]

    match_percentage = round((len(matched_features) / len(expected_features)) * 100, 2)
    is_valid = len(missing_features) == 0

    if require_label and not has_target:
        is_valid = False

    issues = []
    if missing_features:
        issues.append(f"Missing {len(missing_features)} required feature(s): {missing_features[:5]}{'...' if len(missing_features) > 5 else ''}")
    if df.empty:
        issues.append("Uploaded dataset contains zero records.")
        is_valid = False
    if require_label and not has_target:
        issues.append("Ground-truth 'Label' column is required for this operation but was not found.")

    return {
        "is_valid": is_valid,
        "total_records": len(df),
        "total_columns": len(df.columns),
        "expected_feature_count": len(expected_features),
        "matched_feature_count": len(matched_features),
        "missing_feature_count": len(missing_features),
        "match_percentage": match_percentage,
        "missing_features": missing_features,
        "extra_features": extra_features,
        "has_target_label": has_target,
        "issues": issues
    }

def sanitize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Performs initial structural sanitation:
    - Normalizes column names
    - Drops completely duplicate rows
    - Drops duplicate column names if any
    """
    clean_df = df.copy()
    clean_df.columns = [c.strip() for c in clean_df.columns]
    
    # Remove duplicate columns if present
    clean_df = clean_df.loc[:, ~clean_df.columns.duplicated()]
    
    # Drop complete duplicate records
    initial_len = len(clean_df)
    clean_df = clean_df.drop_duplicates()
    dropped_dupes = initial_len - len(clean_df)
    
    return clean_df
