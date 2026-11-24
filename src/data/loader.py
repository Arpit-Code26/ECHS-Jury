"""
Dataset Loader for CyberSentinel.
Supports CSV streaming, chunked reading, and metadata extraction for large datasets.
"""
from typing import Dict, Any, Generator, Optional, Tuple, List, Union
from pathlib import Path
import io
import pandas as pd
import numpy as np
from src.utils.logging_config import logger

def clean_column_names(columns: List[str]) -> List[str]:
    """Strip leading/trailing whitespace and unify column names."""
    return [c.strip() for c in columns]

def inspect_csv_metadata(source: Union[str, Path, io.BytesIO], max_sample_rows: int = 1000) -> Dict[str, Any]:
    """
    Extracts high-level dataset statistics without loading the entire large CSV into memory.
    """
    try:
        # Read header and sample
        df_sample = pd.read_csv(source, nrows=max_sample_rows, encoding="utf-8", low_memory=False)
    except UnicodeDecodeError:
        df_sample = pd.read_csv(source, nrows=max_sample_rows, encoding="latin1", low_memory=False)
        
    df_sample.columns = clean_column_names(list(df_sample.columns))
    
    # Check for target label
    label_col = None
    for col in df_sample.columns:
        if col.lower() == "label":
            label_col = col
            break

    columns = list(df_sample.columns)
    missing_sample = df_sample.isnull().sum().to_dict()
    
    meta = {
        "sample_rows": len(df_sample),
        "column_count": len(columns),
        "columns": columns,
        "missing_values_sample": missing_sample,
        "has_label": label_col is not None,
        "label_column_name": label_col,
    }
    
    return meta

def load_dataset(
    source: Union[str, Path, io.BytesIO],
    nrows: Optional[int] = None,
    chunksize: Optional[int] = None
) -> Union[pd.DataFrame, Generator[pd.DataFrame, None, None]]:
    """
    Load a CSV dataset into a Pandas DataFrame or a chunk generator.
    """
    encoding = "utf-8"
    try:
        if chunksize:
            return pd.read_csv(source, nrows=nrows, chunksize=chunksize, encoding=encoding, low_memory=False)
        else:
            df = pd.read_csv(source, nrows=nrows, encoding=encoding, low_memory=False)
            df.columns = clean_column_names(list(df.columns))
            return df
    except UnicodeDecodeError:
        encoding = "latin1"
        if chunksize:
            return pd.read_csv(source, nrows=nrows, chunksize=chunksize, encoding=encoding, low_memory=False)
        else:
            df = pd.read_csv(source, nrows=nrows, encoding=encoding, low_memory=False)
            df.columns = clean_column_names(list(df.columns))
            return df

def get_class_distribution(df: pd.DataFrame, label_col: str = "Label") -> Dict[str, Any]:
    """
    Computes class counts, imbalance ratio, and percentages.
    """
    if label_col not in df.columns:
        # Check case-insensitive
        matches = [c for c in df.columns if c.strip().lower() == "label"]
        if matches:
            label_col = matches[0]
        else:
            return {"error": f"Label column '{label_col}' not found"}

    counts = df[label_col].value_counts().to_dict()
    total = len(df)
    distribution = {}
    for label, count in counts.items():
        distribution[str(label).strip()] = {
            "count": int(count),
            "percentage": round((count / total) * 100, 2)
        }

    majority_count = max(counts.values()) if counts else 0
    minority_count = min(counts.values()) if counts else 0
    imbalance_ratio = round(majority_count / max(minority_count, 1), 2)

    return {
        "total_records": total,
        "classes": distribution,
        "imbalance_ratio": imbalance_ratio,
        "majority_class": max(counts, key=counts.get) if counts else None,
        "minority_class": min(counts, key=counts.get) if counts else None
    }
