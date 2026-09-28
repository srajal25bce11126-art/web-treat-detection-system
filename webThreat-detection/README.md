# Phishing Detection Backend

A FastAPI-based backend service for detecting phishing websites using Machine Learning (Random Forest) and feature extraction (URL, SSL, and WHOIS).

---

## 📁 Project Structure

```text
phishing-detection-backend/
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI entry point & API routes
│   ├── feature_extraction.py    # URL, SSL, and WHOIS feature extraction
│   ├── schemas.py               # Pydantic request & response models
│   ├── prepare_dataset.py       # Kaggle dataset downloader & preprocessor (>100k rows)
│   ├── train_model.py           # Random Forest model training & evaluation script
│   └── model/
│       └── .gitkeep             # Directory for trained Random Forest model (model.pkl)
├── data/
│   └── .gitkeep                 # Directory for phishing_dataset.csv
├── tests/
│   ├── __init__.py
│   └── test_api.py              # Pytest API integration tests (TestClient)
├── extension/
│   ├── manifest.json            # Chrome extension Manifest V3
│   ├── background.js            # Background service worker with notification handler
│   └── README.md                # Chrome extension install & test instructions
├── scripts/
│   ├── generate_icons.py        # Icon generator script for Chrome extension
│   ├── local_test.py            # Cross-platform local sanity-check test script
│   └── local_test.sh            # Bash sanity-check test script
├── .env.example                 # Example environment variables
├── Procfile                     # Process file for Render / Railway
├── render.yaml                  # Render Blueprint configuration
├── railway.json                 # Railway deployment configuration
├── requirements.txt             # Python dependencies
└── README.md                    # Setup and run instructions
```

---

## ⚙️ Prerequisites

- Python 3.10+ recommended
- `pip` package manager

---

## 🚀 Setup Instructions

### 1. Set Up Virtual Environment

Open a terminal in the project root directory:

```bash
# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
# On Linux / macOS:
source venv/bin/activate
# On Windows (PowerShell):
# .\venv\Scripts\Activate.ps1
```

### 2. Install Dependencies

Install all required packages from `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 3. (Optional) Place Trained Model Artifact

When your Random Forest model is trained, save and place the serialized model file as:

```text
app/model/model.pkl
```

If `model.pkl` is not present, the application will boot gracefully in skeleton mode.

---

## ▶️ Running the Server

Start the FastAPI application with Uvicorn:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Alternatively, run directly with Python:

```bash
python -m app.main
```

The API will be available at `http://127.0.0.1:8000`.

---

## 📖 API Documentation & Endpoints

Once the application is running, visit the interactive Swagger API documentation:

- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### Key Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check endpoint (returns `{"status": "ok"}`) |
| `POST` | `/predict` | Evaluates URL and returns phishing prediction (`Safe` or `Phishing` with confidence) |

#### Example Request (`POST /predict`):
```json
{
  "url": "https://example-phishing-site.com/login"
}
```

#### Example Response:
```json
{
  "url": "https://example-phishing-site.com/login",
  "prediction": "Safe",
  "confidence": 0.0
}
```

---

## 📊 Dataset Preparation (Kaggle)

To download and process a large-scale phishing dataset (>100,000 rows):

We use the **PhiUSIIL Phishing URL Dataset** (`ndarvind/phiusiil-phishing-url-dataset`), which contains **235,795 rows** (134,850 safe and 100,945 phishing).

### 🔑 Kaggle Authentication Setup

If the Kaggle API requires authentication:
1. Log into your Kaggle account: [https://www.kaggle.com](https://www.kaggle.com)
2. Go to **Settings** (click your profile avatar in the upper-right corner).
3. Scroll down to the **API** section and click **Create New Token**.
4. This downloads a `kaggle.json` file containing your credentials:
   ```json
   {"username": "your_kaggle_username", "key": "your_kaggle_api_key"}
   ```
5. Place the `kaggle.json` file in:
   - **Linux / macOS**: `~/.kaggle/kaggle.json` (ensure permissions: `chmod 600 ~/.kaggle/kaggle.json`)
   - **Windows**: `C:\Users\<YourUsername>\.kaggle\kaggle.json`
   - *Or set environment variables:*
     ```bash
     export KAGGLE_USERNAME="your_kaggle_username"
     export KAGGLE_KEY="your_kaggle_api_key"
     ```

### Run the Dataset Preparation Script

```bash
python app/prepare_dataset.py
```

This script will:
1. Download the dataset using `kagglehub` (or `kaggle` API fallback).
2. Display initial shape (e.g. `235,795 rows × 56 columns`) and all column names.
3. Map and extract features matching `app/feature_extraction.py`.
4. Drop missing values.
5. Save the cleaned CSV to `data/phishing_dataset.csv`.
6. Confirm final row count (>100k rows).

---

## 🧠 Model Training

To train the Random Forest Classifier on your labeled dataset:

1. Place your dataset CSV file at `data/phishing_dataset.csv`.
2. Ensure it contains the feature columns matching `feature_extraction.py` plus the target `label` column (0 = safe, 1 = phishing):
   - `url_length`
   - `num_dots`
   - `has_at_symbol`
   - `is_ip_address`
   - `use_https`
   - `ssl_valid`
   - `domain_age_days`
   - `num_redirects`
   - `label` (0 or 1)

3. Run the training script:
```bash
python app/train_model.py
```

Optional training arguments:
```bash
python app/train_model.py --data data/phishing_dataset.csv --model-out app/model/model.pkl --test-size 0.2 --n-estimators 100
```
The script utilizes all available CPU cores (`n_jobs=-1`), logs elapsed training time using Python's `time` module, displays a full breakdown of the confusion matrix (True/False Positives/Negatives), prints test set evaluation metrics (Accuracy, Precision, Recall, F1 score), and saves the trained model to `app/model/model.pkl`.

---

## 🧪 Testing

### Running Automated Tests
To run unit and integration tests using `pytest` and FastAPI's `TestClient`:

```bash
pytest tests/ -v
```

### Local Sanity Check Scripts
Quickly test the API end-to-end locally (boots `uvicorn`, waits 2s, sends 3 test URLs to `/predict`, prints results, and cleans up):

- **Cross-Platform (Windows / Linux / macOS)**:
  ```bash
  python scripts/local_test.py
  ```
- **Bash (Linux / macOS)**:
  ```bash
  chmod +x scripts/local_test.sh
  ./scripts/local_test.sh
  ```

### Example `curl` Commands

**1. Health Check:**
```bash
curl -X GET http://localhost:8000/
```
*Expected Response:*
```json
{"status": "ok"}
```

**2. Test Known-Safe URL:**
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**3. Test Known Phishing-Style URL:**
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.100/login.php?account=verify@paypal-update.net"}'
```

---

## 🧩 Chrome Extension (Manifest V3)

A zero-popup Chrome extension that triggers real-time phishing URL inspection via desktop system notifications.

### How to Install:
1. Ensure your backend is running (`uvicorn app.main:app --port 8000`).
2. Generate extension icons (if not already present):
   ```bash
   python scripts/generate_icons.py
   ```
3. In Chrome, navigate to `chrome://extensions`.
4. Enable **Developer mode** (toggle in upper-right corner).
5. Click **Load unpacked** and select the `extension/` directory.
6. Click the extension icon on any active tab to trigger a real-time scan and system notification!

---

## ☁️ Deployment (Render / Railway)

This repository includes a [`Procfile`](Procfile), [`render.yaml`](render.yaml), and [`railway.json`](railway.json) ready for deployment.

### 1. Deploying on Render

#### Option A: Automatic via Blueprint
1. Push this project repository to GitHub or GitLab.
2. Go to [Render Dashboard](https://dashboard.render.com/) -> **New** -> **Blueprint**.
3. Select your repository. Render will automatically detect [`render.yaml`](render.yaml) and configure the service.

#### Option B: Manual Web Service Setup
1. In the Render Dashboard, click **New +** -> **Web Service**.
2. Connect your Git repository.
3. Configure the following service settings:
   - **Environment**: `Python 3`
   - **Build Command**:
     ```bash
     pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     uvicorn app.main:app --host 0.0.0.0 --port $PORT
     ```
4. Configure **Environment Variables** under the service's **Environment** tab:
   - `PYTHON_VERSION`: `3.11.0`
   - `VIRUSTOTAL_API_KEY`: *(Optional)* Your VirusTotal API key if using external threat feeds.

---

### 2. Deploying on Railway

1. Install the Railway CLI or visit [Railway.app](https://railway.app/).
2. Click **New Project** -> **Deploy from GitHub repo**.
3. Railway will auto-detect the [`Procfile`](Procfile) and [`railway.json`](railway.json).
4. Set the Start Command (if prompted or in service settings):
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port $PORT
   ```
5. In the **Variables** tab, add any required environment variables (e.g. `VIRUSTOTAL_API_KEY`).

---

### 🔐 Environment Variables Reference

| Variable | Required | Description | Default / Example |
|---|---|---|---|
| `PORT` | Auto | Port provided by Render or Railway | Assigned automatically (`$PORT`) |
| `PYTHON_VERSION` | Recommended | Python runtime version | `3.11.0` |
| `VIRUSTOTAL_API_KEY` | Optional | API key for external threat intelligence checks | `your_api_key_here` |

> [!NOTE]
> Ensure that your trained model artifact [`app/model/model.pkl`](app/model/) is tracked in Git or created during a build hook before deployment, so that the production API boots with inference enabled.

---

## 🔨 Next Steps

1. **Supply Dataset**: Place `phishing_dataset.csv` in the `data/` folder.
2. **Train Model**: Run `python app/train_model.py` to generate `app/model/model.pkl`.
3. **Run API / Deploy**: Test locally with `uvicorn app.main:app --reload` or deploy to Render/Railway.



