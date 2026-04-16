import os
import warnings
import joblib
import pandas as pd
import numpy as np

warnings.filterwarnings('ignore', category=UserWarning)

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'random_forest_pipeline.joblib')
CLEANED_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cleaned_dataset_sample.csv')

_model = None
_feature_info = None


def _patch_imputers(obj, depth=0):
    """Fix sklearn version mismatch: older models store _fit_dtype but 1.6+ expects _fill_dtype."""
    from sklearn.impute import SimpleImputer
    if isinstance(obj, SimpleImputer):
        if hasattr(obj, '_fit_dtype') and not hasattr(obj, '_fill_dtype'):
            obj._fill_dtype = obj._fit_dtype
        elif hasattr(obj, 'statistics_') and not hasattr(obj, '_fill_dtype'):
            obj._fill_dtype = obj.statistics_.dtype
    for attr in ('steps', 'transformers', 'transformer_list'):
        container = getattr(obj, attr, None)
        if container:
            for item in container:
                if isinstance(item, (list, tuple)):
                    for sub in item:
                        if hasattr(sub, '__dict__'):
                            _patch_imputers(sub, depth + 1)
                elif hasattr(item, '__dict__'):
                    _patch_imputers(item, depth + 1)
    if hasattr(obj, 'named_steps'):
        for v in obj.named_steps.values():
            _patch_imputers(v, depth + 1)
    if hasattr(obj, 'named_transformers_'):
        for v in obj.named_transformers_.values():
            _patch_imputers(v, depth + 1)


def get_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
        _patch_imputers(_model)
    return _model


def get_feature_info():
    global _feature_info
    if _feature_info is not None:
        return _feature_info

    model = get_model()
    feature_names = list(model.feature_names_in_)

    df = pd.read_csv(CLEANED_CSV, nrows=2000)
    info = {}
    for col in feature_names:
        if col not in df.columns:
            info[col] = {'type': 'numeric', 'median': 0.0}
            continue
        if pd.api.types.is_numeric_dtype(df[col]):
            info[col] = {
                'type': 'numeric',
                'median': float(df[col].median()) if not df[col].dropna().empty else 0.0
            }
        else:
            vals = df[col].dropna().unique().tolist()[:50]
            mode_val = str(df[col].mode().iloc[0]) if not df[col].mode().empty else ''
            info[col] = {
                'type': 'categorical',
                'values': [str(v) for v in vals],
                'mode': mode_val
            }
    _feature_info = info
    return info


def feature_info_from_csv(file_stream, nrows=2000):
    """Extract feature info from any uploaded CSV, aligned to model features where possible."""
    model = get_model()
    model_features = list(model.feature_names_in_)

    df = pd.read_csv(file_stream, nrows=nrows, low_memory=False, on_bad_lines='skip')

    # Drop target-like columns
    for col in ('Label', ' Label', 'label', 'Predicted_Label'):
        if col in df.columns:
            df = df.drop(columns=[col])

    info = {}
    # Prefer model feature order; fall back to CSV column order for extra cols
    all_cols = []
    for c in model_features:
        if c in df.columns:
            all_cols.append(c)
    for c in df.columns:
        if c not in all_cols:
            all_cols.append(c)

    for col in all_cols:
        if col not in df.columns:
            info[col] = {'type': 'numeric', 'median': 0.0, 'in_model': col in model_features}
            continue
        in_model = col in model_features
        if pd.api.types.is_numeric_dtype(df[col]):
            info[col] = {
                'type': 'numeric',
                'median': float(df[col].median()) if not df[col].dropna().empty else 0.0,
                'in_model': in_model,
            }
        else:
            vals = df[col].dropna().unique().tolist()[:50]
            mode_val = str(df[col].mode().iloc[0]) if not df[col].mode().empty else ''
            info[col] = {
                'type': 'categorical',
                'values': [str(v) for v in vals],
                'mode': mode_val,
                'in_model': in_model,
            }
    return info


def predict_single(row_dict):
    model = get_model()
    feature_names = list(model.feature_names_in_)
    row = {}
    for col in feature_names:
        val = row_dict.get(col)
        if val is None or val == '':
            row[col] = np.nan
        else:
            try:
                row[col] = float(val)
            except (ValueError, TypeError):
                row[col] = val
    X = pd.DataFrame([row], columns=feature_names)
    pred = model.predict(X)
    result = {'prediction': str(pred[0])}
    if hasattr(model, 'predict_proba'):
        probs = model.predict_proba(X)[0]
        classes = list(model.classes_)
        class_probs = sorted(zip(classes, probs), key=lambda x: x[1], reverse=True)
        result['probabilities'] = [{'class': c, 'prob': round(float(p) * 100, 2)} for c, p in class_probs[:5]]
    return result
