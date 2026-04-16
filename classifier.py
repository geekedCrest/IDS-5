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


def get_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
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
