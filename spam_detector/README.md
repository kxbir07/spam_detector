# SpamSentinel 🛡️
### AI-Powered Spam Detection with Sender Trust Scoring & URL Threat Analysis

A smart email spam detection system that goes beyond basic filtering. Built with Flask + scikit-learn.

---

## Features

| Feature | Description |
|---|---|
| 🤖 **ML Spam Classifier** | TF-IDF + Logistic Regression pipeline trained on 18k+ emails |
| 🎯 **Sender Trust Engine** | Automatic reputation scoring (0–100) with 5 categories |
| 🔗 **URL Threat Scanner** | Heuristic + Google Safe Browsing analysis of links in emails |
| 🚨 **Auto Alerts** | Notifies you when a sender crosses spammer/verified thresholds |
| 📊 **Dashboard** | Full sender history, alert management, email log |

---

## Project Structure

```
spam_detector/
├── app.py              ← Flask web application
├── train.py            ← Model training script
├── trust_engine.py     ← Sender reputation scoring
├── url_scanner.py      ← URL threat analysis
├── database.py         ← SQLite setup
├── requirements.txt
├── data/
│   └── spam_or_not_spam.csv   ← (you download this)
├── models/
│   └── spam_model.pkl         ← (auto-generated after training)
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── result.html
│   └── dashboard.html
└── README.md
```

---

## Setup Instructions (Windows)

### Step 1 — Install Python
Download and install Python 3.10 or newer from https://python.org
Make sure to check **"Add Python to PATH"** during installation.

### Step 2 — Open Terminal
Open **Command Prompt** or **PowerShell** in the project folder:
```
cd path\to\spam_detector
```

### Step 3 — Create Virtual Environment (recommended)
```bash
python -m venv venv
venv\Scripts\activate
```
You should see `(venv)` appear in your terminal prompt.

### Step 4 — Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 5 — Download the Dataset
1. Go to: https://www.kaggle.com/datasets/ozlerhakan/spam-or-not-spam-dataset
2. Sign in to Kaggle (free account)
3. Download `spam_or_not_spam.csv`
4. Place it inside the `data/` folder of this project

### Step 6 — Train the Model
```bash
python train.py
```
This will:
- Load the dataset
- Train Naive Bayes and Logistic Regression models
- Print accuracy scores for both
- Save the best model to `models/spam_model.pkl`

Expected output:
```
[Data] Loaded 18000+ samples
[Train] Logistic Regression Accuracy: 0.9847
[Train] ✅ Best model: Logistic Regression
[Train] Model saved successfully.
```

### Step 7 — Initialize Database & Run
```bash
python app.py
```

Open your browser and go to: **http://localhost:5000**

---

## Optional: Google Safe Browsing API (Free)

For enhanced URL scanning, you can add Google's Safe Browsing API:

1. Go to https://console.cloud.google.com
2. Enable "Safe Browsing API"
3. Create an API key
4. Set it as an environment variable before running:

**Windows (Command Prompt):**
```
set SAFE_BROWSING_API_KEY=your_key_here
python app.py
```

**Windows (PowerShell):**
```
$env:SAFE_BROWSING_API_KEY="your_key_here"
python app.py
```

The URL scanner works without this key — it will use heuristic analysis only.

---

## How the Trust Scoring Works

Every sender starts at a score of **50/100**.

| Event | Score Change |
|---|---|
| Email classified as Ham | +8 points |
| Email classified as Spam | −12 points |

### Categories

| Category | Score Range | Meaning |
|---|---|---|
| ✅ VERIFIED | 80–100 | Trusted sender, consistently clean |
| 👍 TRUSTED | 65–79 | Mostly clean history |
| ❓ NEUTRAL | 40–64 | Unknown / insufficient data |
| ⚠️ SUSPICIOUS | 20–39 | Multiple spam hits |
| 🚫 SPAMMER | 0–19 | Confirmed bad actor |

**Alerts fire automatically when:**
- Score drops below 20 after 3+ emails → **Spammer Alert**
- Score rises above 80 after 5+ ham emails → **Auto-Verified**

You can manually override any sender from the dashboard or result page.

---

## How URL Scanning Works

The scanner checks every URL in the email body for:

- IP addresses used as domain (e.g. `http://192.168.1.1/login`)
- Suspicious TLDs (`.tk`, `.ml`, `.xyz`, `.click`, etc.)
- Phishing keywords in the URL (`login`, `verify`, `password`, `secure`, etc.)
- Excessive subdomains (e.g. `secure.login.verify.badsite.com`)
- Misleading brand names in subdomain (`paypal.evilsite.com`)
- URL shorteners (bit.ly, tinyurl, etc.)
- HTTP instead of HTTPS
- Unusually long URLs

Results are categorized as 🟢 SAFE / 🟠 SUSPICIOUS / 🔴 DANGEROUS.

---

## Team Contributions

Each module is clearly separated for individual contribution tracking:

| File | Responsible For |
|---|---|
| `train.py` + `database.py` | ML pipeline, data preprocessing |
| `trust_engine.py` | Sender reputation system |
| `url_scanner.py` | URL threat analysis |
| `app.py` + templates | Flask app, UI integration |

---

## Tech Stack

- **Python 3.10+**
- **Flask** — Web framework
- **scikit-learn** — TF-IDF + ML models
- **SQLite** — Sender trust database (no setup needed)
- **tldextract** — Domain parsing for URL analysis
- **joblib** — Model serialization
