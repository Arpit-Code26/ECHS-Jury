"""
Robust Preprocessing Pipeline for CyberSentinel.
Handles column normalization, data leakage prevention, infinity replacement,
missing value imputation, and feature scaling.
"""
from typing import Tuple, Optional, List, Dict, Any, Union
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
import joblib

from config.model_config import (
    CANONICAL_FEATURES,
    COLUMNS_TO_DROP,
    TARGET_COLUMN,
    BINARY_LABEL_BENIGN,
    BINARY_LABEL_ATTACK
)
from src.utils.logging_config import logger


class CyberSentinelPreprocessor(BaseEstimator, TransformerMixin):
    """
    Unified Preprocessor for CyberSentinel.
    Fitted strictly on training data; safe for inference transformation.
    """
    def __init__(self, feature_columns: Optional[List[str]] = None):
        self.feature_columns = feature_columns or CANONICAL_FEATURES
        self.imputer: Optional[SimpleImputer] = None
        self.scaler: Optional[StandardScaler] = None
        self.fitted_feature_names_: List[str] = []
        self.is_fitted: bool = False
        self.feature_medians_: Dict[str, float] = {}

    def fit(self, X: pd.DataFrame, y: Optional[Union[pd.Series, np.ndarray]] = None):
        """Fit imputer and scaler on numeric features."""
        X_clean = self._clean_and_align_features(X, is_training=True)
        
        # Fit Imputer on median
        self.imputer = SimpleImputer(strategy="median")
        X_imputed = self.imputer.fit_transform(X_clean)
        
        # Store feature medians for quick fallback
        for idx, col in enumerate(self.fitted_feature_names_):
            self.feature_medians_[col] = float(self.imputer.statistics_[idx])
            
        # Fit Scaler
        self.scaler = StandardScaler()
        self.scaler.fit(X_imputed)
        
        self.is_fitted = True
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Transform incoming DataFrame using fitted imputer and scaler."""
        if not self.is_fitted:
            raise RuntimeError("CyberSentinelPreprocessor has not been fitted yet!")
            
        X_clean = self._clean_and_align_features(X, is_training=False)
        X_imputed = self.imputer.transform(X_clean)
        X_scaled = self.scaler.transform(X_imputed)
        return X_scaled

    def fit_transform(self, X: pd.DataFrame, y: Optional[Union[pd.Series, np.ndarray]] = None) -> np.ndarray:
        return self.fit(X, y).transform(X)

    def _clean_and_align_features(self, df: pd.DataFrame, is_training: bool = False) -> pd.DataFrame:
        """
        Strips whitespace, removes data-leakage columns, replaces infinities,
        and ensures strict canonical feature alignment.
        """
        clean_df = df.copy()
        clean_df.columns = [c.strip() for c in clean_df.columns]
        
        # Remove target column if present in feature matrix
        target_cols = [c for c in clean_df.columns if c.lower() == TARGET_COLUMN.lower()]
        if target_cols:
            clean_df = clean_df.drop(columns=target_cols)
            
        # Remove known data-leakage / non-predictive identifying columns
        for drop_col in COLUMNS_TO_DROP:
            matches = [c for c in clean_df.columns if c.lower() == drop_col.lower()]
            if matches:
                clean_df = clean_df.drop(columns=matches)
                
        # Remove any remaining non-canonical or duplicate columns
        clean_df = clean_df.loc[:, ~clean_df.columns.duplicated()]
        
        # Ensure all canonical features exist; if missing in inference, impute with 0.0 or median
        for col in self.feature_columns:
            if col not in clean_df.columns:
                if is_training:
                    # During training, missing canonical feature is filled with 0.0
                    clean_df[col] = 0.0
                else:
                    # In inference, use fitted median or 0.0
                    clean_df[col] = self.feature_medians_.get(col, 0.0)
                    
        # Retain canonical order
        clean_df = clean_df[self.feature_columns]
        
        # Convert to numeric, replace infinities with NaN for the imputer
        clean_df = clean_df.apply(pd.to_numeric, errors="coerce")
        clean_df = clean_df.replace([np.inf, -np.inf], np.nan)
        
        if is_training:
            self.fitted_feature_names_ = list(clean_df.columns)
            
        return clean_df

    def save(self, filepath: str) -> None:
        """Serialize preprocessor to disk."""
        joblib.dump(self, filepath)
        logger.info(f"Preprocessor successfully saved to: {filepath}")

    @classmethod
    def load(cls, filepath: str) -> "CyberSentinelPreprocessor":
        """Load serialized preprocessor."""
        obj = joblib.load(filepath)
        if not isinstance(obj, CyberSentinelPreprocessor):
            raise TypeError("Loaded file is not an instance of CyberSentinelPreprocessor")
        logger.info(f"Preprocessor successfully loaded from: {filepath}")
        return obj


def prepare_labels(labels: pd.Series) -> Tuple[np.ndarray, np.ndarray, LabelEncoder]:
    """
    Prepares ground-truth labels for both binary and multiclass tasks.
    Returns:
      - y_binary (0 for BENIGN, 1 for ATTACK)
      - y_multiclass (encoded integers)
      - label_encoder (fitted Scikit-Learn LabelEncoder)
    """
    # Clean label strings
    clean_series = labels.astype(str).str.strip()
    
    # Binary labels: 0 = BENIGN, 1 = ATTACK
    y_binary = np.where(clean_series.str.upper() == "BENIGN", 0, 1)
    
    # Multiclass labels
    le = LabelEncoder()
    y_multiclass = le.fit_transform(clean_series)
    
    return y_binary, y_multiclass, le
