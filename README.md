# 🔐 Password Strength Analyzer

A production-ready Streamlit web app that evaluates password strength using
the [zxcvbn](https://github.com/dwolfhub/zxcvbn-python) library.
Passwords are **never stored, logged, or transmitted** — all analysis runs
locally in your browser session.

---

## Features

| Feature | Detail |
|---|---|
| Realistic strength scoring | zxcvbn scores 0–4, far more accurate than simple rule checkers |
| Crack-time estimates | Online (throttled & unthrottled) and offline (slow & fast hash) |
| Character composition | Length, uppercase, lowercase, digits, symbols |
| Weakness detection | Repeated chars, common sequences (`123`, `qwerty`, …) |
| Personal info check | Optionally enter name / email / birth year; zxcvbn flags matches |
| Password generator | Cryptographically secure (`secrets` module), 16–20 chars |
| Show / hide toggle | Reveal the typed password on demand |
| Expandable breakdown | Entropy estimate + full crack-time table |

---

## Quick start

### 1. Clone / download

```bash
git clone <your-repo-url>
cd <repo-folder>
```

### 2. Create a virtual environment (recommended)

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
streamlit run app.py
```

Streamlit will print a local URL (usually `http://localhost:8501`).
Open it in your browser.

---

## Deploying to Streamlit Community Cloud

1. Push the repository (containing `app.py` and `requirements.txt`) to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io) and click **New app**.
3. Select your repository, branch, and set **Main file path** to `app.py`.
4. Click **Deploy** — Streamlit Cloud installs dependencies automatically.

---

## Project structure

```
.
├── app.py            # Main Streamlit application
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `streamlit` | Web UI framework |
| `zxcvbn` | Realistic password strength estimation |

Both packages are pure Python and have no system-level requirements.

---

## Privacy note

The app contains **no network calls, no analytics, no logging, and no
persistence**. The password you type exists only in the running Python
process's memory for the duration of the analysis and is discarded on
the next interaction. No data is written to disk.
