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
    # ── Flow identity ──────────────────────────────────────────────────────
    ('dst_port',           'Destination Port',          '80=HTTP  443=HTTPS  22=SSH  21=FTP  53=DNS  3389=RDP'),
    ('protocol',           'Protocol',                  '6 = TCP     17 = UDP     1 = ICMP     0 = Other'),
    ('flow_duration',      'Flow Duration (µs)',        'Total session length in microseconds'),
    # ── Packet counts ──────────────────────────────────────────────────────
    ('tot_fwd_pkts',       'Total Fwd Packets',         'Packets sent from source → destination'),
    ('tot_bwd_pkts',       'Total Bwd Packets',         'Packets sent from destination → source'),
    ('tot_len_fwd_pkts',   'Total Fwd Payload (bytes)', 'Total byte volume in the forward direction'),
    ('tot_len_bwd_pkts',   'Total Bwd Payload (bytes)', 'Total byte volume in the backward direction'),
    # ── Flow rates ─────────────────────────────────────────────────────────
    ('flow_byts_s',        'Flow Bytes / s',            'Total bytes transferred per second'),
    ('flow_pkts_s',        'Flow Packets / s',          'Total packets per second (both directions)'),
    ('fwd_pkts_s',         'Fwd Packets / s',           'Forward-direction packet rate'),
    ('bwd_pkts_s',         'Bwd Packets / s',           'Backward-direction packet rate'),
    # ── Packet sizes ───────────────────────────────────────────────────────
    ('fwd_pkt_len_max',    'Fwd Pkt Length Max',        'Largest forward-direction packet (bytes)'),
    ('pkt_len_mean',       'Mean Packet Length',        'Average size of all packets in the flow'),
    ('pkt_len_std',        'Packet Length Std Dev',     'Variance in packet sizes — high = mixed traffic'),
    # ── Timing ─────────────────────────────────────────────────────────────
    ('flow_iat_mean',      'Flow IAT Mean (µs)',        'Average inter-arrival time between packets'),
    ('init_fwd_win_byts',  'Init Fwd Window (bytes)',   'Initial TCP receive window size (forward)'),
    # ── TCP Flags ──────────────────────────────────────────────────────────
    ('syn_flag_cnt',       'SYN Flag Count',            'SYN flags seen — high value signals SYN flood'),
    ('ack_flag_cnt',       'ACK Flag Count',            'ACK flags — normally matches packet count'),
    ('fin_flag_cnt',       'FIN Flag Count',            'FIN flags — graceful connection teardown'),
    ('rst_flag_cnt',       'RST Flag Count',            'RST flags — forced resets, scanning indicator'),
    ('psh_flag_cnt',       'PSH Flag Count',            'PSH flags — data push events in the flow'),
    # ── Ratios ─────────────────────────────────────────────────────────────
    ('down_up_ratio',      'Down / Up Ratio',           'Bytes received ÷ bytes sent; >1 = download heavy'),
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
    _model = joblib.load(MODEL_PATH, mmap_mode='r')


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


def _norm_col(name):
    """Normalise a CSV column name to internal snake_case (e.g. 'Dst Port' → 'dst_port')."""
    import re
    return re.sub(r'[\s/\-\.]+', '_', name.strip().lower()).strip('_')


def feature_info_from_csv(file_stream, nrows=2000):
    _load_meta()
    df = pd.read_csv(file_stream, nrows=nrows, low_memory=False, on_bad_lines='skip')

    # Drop label / metadata columns
    drop_candidates = ('Label', ' Label', 'label', 'Predicted_Label',
                       '__source_file', 'Timestamp', ' Timestamp',
                       'Src IP', 'Dst IP', 'Src Port', ' Source Port')
    df = df.drop(columns=[c for c in drop_candidates if c in df.columns])

    # Build a normalised-name → original-name lookup so we can match
    # internal names like 'dst_port' against CSV headers like 'Dst Port'
    col_map = {_norm_col(c): c for c in df.columns}

    # Some CSV variants use abbreviated names that don't normalise to the
    # model's internal names — add explicit aliases here.
    _ALIASES = {
        'tot_len_fwd_pkts': ['totlen_fwd_pkts', 'total_length_of_fwd_packets',
                             'total_fwd_packets_length', 'totlen_fwd_pkts'],
        'tot_len_bwd_pkts': ['totlen_bwd_pkts', 'total_length_of_bwd_packets',
                             'total_bwd_packets_length'],
    }
    for internal, candidates in _ALIASES.items():
        if internal not in col_map:
            for alias in candidates:
                if alias in col_map:
                    col_map[internal] = col_map[alias]
                    break

    means = dict(zip(_feat_cols, _scaler.mean_))
    info = {}
    for col, label, desc in KEY_FEATURES:
        csv_col = col_map.get(col)          # e.g. col='dst_port' → csv_col='Dst Port'
        if csv_col and pd.api.types.is_numeric_dtype(df[csv_col]):
            series = df[csv_col].dropna()
            med = float(series.median()) if not series.empty else means.get(col, 0.0)
        else:
            med = means.get(col, 0.0)
        info[col] = {
            'label': label,
            'description': desc,
            'type': 'numeric',
            'median': round(med, 4),
        }
    return info
