# µIDS Sentinel Grid

A Python/Flask-based Network Intrusion Detection System (IDS) with a Wireshark-inspired dark-theme web dashboard, real-time packet simulation via WebSockets, rule-based detection, and a trained Random Forest ML classifier.

---

## Features

- Real-time packet capture simulation with live WebSocket updates
- Rule-based intrusion detection (Snort-style rules)
- ML classifier using a trained Random Forest pipeline (12 attack classes)
- Wireshark-style dark UI with Packets, Alerts, Statistics, Classifier, and Rules tabs
- CSV upload with live progress bar (rows estimated, GB remaining)
- Filterable packet list, threat level indicator, traffic overview charts

---

## Requirements

- Python 3.9 or higher
- pip

---

## Step-by-Step Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

### 2. (Recommended) Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> **Important:** If you see a scapy-related import error after installing, run:
> ```bash
> pip uninstall scapy-python3 -y
> pip install scapy --force-reinstall --no-deps
> ```
> The `scapy-python3` package conflicts with `scapy` and must not be installed.

### 4. Add the ML model file

The Random Forest model file (`random_forest_pipeline.joblib`) is **not included in the repo** due to its size (~41 MB).

Place your model file in the project root:

```
your-repo/
├── app.py
├── classifier.py
├── random_forest_pipeline.joblib   <-- put it here
├── cleaned_dataset_sample.csv      <-- optional: 2000-row sample for default features
└── ...
```

The model must be a scikit-learn `Pipeline` saved with `joblib.dump()`. It should expose `feature_names_in_` and `classes_`.

If you trained the model yourself, export it like this:

```python
import joblib
joblib.dump(pipeline, 'random_forest_pipeline.joblib')
```

### 5. Run the application

```bash
python3 app.py
```

The server starts on **http://localhost:5000**

Open that URL in your browser. You should see the dashboard with a green "Connected" badge in the bottom right.

---

## Using the Dashboard

| Action | How |
|---|---|
| Start packet capture | Click **Start** in the toolbar |
| Pause / Stop capture | Click **Pause** or **Stop** |
| Filter packets | Type in the Filter bar (e.g. `tcp`, `192.168.0.1`, `CRITICAL`) |
| View intrusion alerts | Click the **Alerts** tab |
| View traffic stats | Click the **Statistics** tab or **Stats** toolbar button |
| Run ML classifier | Click **Classifier** tab → fill features → **Predict** |
| Load your own CSV | In Classifier tab → **Load CSV** → pick a `.csv` file |
| View/edit rules | Click **Rules** tab |
| Export capture | Click **Save** in the toolbar |

---

## ML Classifier

The classifier uses a trained Random Forest pipeline and can detect these traffic classes:

- BENIGN
- Bot
- DDoS
- DoS GoldenEye
- DoS Hulk
- DoS Slowhttptest
- DoS slowloris
- FTP-Patator
- Heartbleed
- Infiltration
- PortScan
- SSH-Patator

Click **Fill Defaults** to populate all 81 feature fields with median values from the training data, then click **Predict** to classify.

To use your own dataset: click **Load CSV**, select any `.csv` file — the form rebuilds with your columns. Features the model doesn't recognize are dimmed but can still be submitted.

---

## Rule Syntax

Rules follow this structure:

```
PROTO [!]IP|any:[!]PORT(RANGE)|any <>|-> [!]IP|any:[!]PORT(RANGE)|any *PAYLOAD
```

Example:

```
ICMP 1.1.1.1:any -> 192.168.178.22:any *
TCP !192.0.0.1:[0-8000] <> 127.0.0.1:!8080 *
```

- `PROTO` — TCP, UDP, or ICMP
- `[!]IP|any` — IP address; `!` negates, `any` matches all
- `[!]PORT(RANGE)|any` — port or range like `[80-443]`; `<>` = bidirectional, `->` = one-way
- `*PAYLOAD` — payload pattern to match

---

## Project Structure

```
├── app.py                        # Flask app + Socket.IO server
├── classifier.py                 # ML model loading and prediction logic
├── rules.py                      # Rule engine
├── signature.py                  # Snort rule parser
├── requirements.txt
├── random_forest_pipeline.joblib # ML model (add manually — not in repo)
├── cleaned_dataset_sample.csv    # Sample CSV for default feature values
├── templates/
│   └── index.html                # Single-page dashboard
└── static/
    ├── css/style.css
    └── js/app.js
```

---

## Troubleshooting

**Blank page or "Cannot connect"**
- Make sure the server is running: `python3 app.py`
- Check the terminal for errors

**Scapy import error**
- Run: `pip uninstall scapy-python3 -y && pip install scapy --force-reinstall --no-deps`

**Classifier predict returns an error**
- Make sure `random_forest_pipeline.joblib` is in the project root
- The model must be a scikit-learn Pipeline with `feature_names_in_` set

**Port 5000 already in use**
- Kill the existing process or change the port at the bottom of `app.py`:
  ```python
  socketio.run(app, host='0.0.0.0', port=5001, ...)
  ```

---

## License

MIT
