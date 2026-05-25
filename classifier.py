import os
import warnings
import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings('ignore', category=UserWarning)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(BASE_DIR, 'uploaded', 'cyber_rf_model.joblib')
SCALER_PATH = os.path.join(BASE_DIR, 'uploaded', 'cyber_scaler.joblib')
ENCODER_PATH = os.path.join(BASE_DIR, 'uploaded', 'cyber_encoder.joblib')

KEY_FEATURES = [
    ('dst_port',        'Destination Port',       '80=HTTP  443=HTTPS  22=SSH  21=FTP  53=DNS'),
    ('protocol',        'Protocol',               '6 = TCP     17 = UDP     1 = ICMP     0 = Other'),
    ('flow_duration',   'Flow Duration (µs)',     'Total session length in microseconds'),
    ('tot_fwd_pkts',    'Total Fwd Packets',      'Packets sent from source → destination'),
    ('tot_bwd_pkts',    'Total Bwd Packets',      'Packets sent from destination → source'),
    ('fwd_pkt_len_max', 'Fwd Packet Length Max',  'Largest forward-direction packet size (bytes)'),
    ('flow_byts_s',     'Flow Bytes / s',         'Total bytes transferred per second'),
]

_scaler    = None
_encoder   = None
_model     = None
_feat_cols = None


def _load_meta():
    global _scaler, _encoder, _feat_cols
    if _scaler is not None:
        return
    _scaler    = joblib.load(SCALER_PATH)
    _encoder   = joblib.load(ENCODER_PATH)
    _feat_cols = list(_scaler.feature_names_in_)


def _load_model():
    global _model
    if _model is not None:
        return
    _load_meta()
    _model = joblib.load(MODEL_PATH)


def get_model():
    _load_model()
    return _model


def get_model_metadata():
    _load_meta()
    return {
        'classes': list(_encoder.classes_),
        'n_features': len(_feat_cols),
        'dataset': 'CICIDS 2017 / 2018',
        'algorithm': 'Random Forest',
        'estimators': 200,
        'training_samples': 916666,
    }


def get_feature_info():
    _load_meta()
    means = dict(zip(_feat_cols, _scaler.mean_))
    info = {}
    for col, label, desc in KEY_FEATURES:
        info[col] = {
            'label': label,
            'description': desc,
            'type': 'numeric',
            'median': round(float(means.get(col, 0.0)), 4),
        }
    return info


def predict_single(row_dict):
    _load_model()
    means = dict(zip(_feat_cols, _scaler.mean_))
    row = [means.get(col, 0.0) for col in _feat_cols]
    col_idx = {col: i for i, col in enumerate(_feat_cols)}
    for key, val in row_dict.items():
        if key in col_idx and val not in (None, ''):
            try:
                row[col_idx[key]] = float(val)
            except (ValueError, TypeError):
                pass
    X = np.array(row, dtype=float).reshape(1, -1)
    X_scaled = _scaler.transform(X)
    pred_enc = _model.predict(X_scaled)
    pred_label = _encoder.inverse_transform(pred_enc)[0]
    result = {'prediction': str(pred_label)}
    if hasattr(_model, 'predict_proba'):
        probs = _model.predict_proba(X_scaled)[0]
        classes = list(_encoder.classes_)
        class_probs = sorted(zip(classes, probs), key=lambda x: x[1], reverse=True)
        result['probabilities'] = [
            {'class': c, 'prob': round(float(p) * 100, 2)}
            for c, p in class_probs[:5]
        ]
    return result


def feature_info_from_csv(file_stream, nrows=2000):
    _load_meta()
    df = pd.read_csv(file_stream, nrows=nrows, low_memory=False, on_bad_lines='skip')
    for col in ('Label', ' Label', 'label', 'Predicted_Label'):
        if col in df.columns:
            df = df.drop(columns=[col])
    means = dict(zip(_feat_cols, _scaler.mean_))
    info = {}
    for col, label, desc in KEY_FEATURES:
        if col in df.columns and pd.api.types.is_numeric_dtype(df[col]):
            med = float(df[col].median()) if not df[col].dropna().empty else means.get(col, 0.0)
        else:
            med = means.get(col, 0.0)
        info[col] = {
            'label': label,
            'description': desc,
            'type': 'numeric',
            'median': round(med, 4),
        }
    return info
