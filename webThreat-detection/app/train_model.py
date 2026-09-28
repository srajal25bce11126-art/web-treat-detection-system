"""
Model training pipeline for phishing detection.
Loads dataset from CSV, trains a Random Forest Classifier, evaluates metrics,
and serializes the trained model to app/model/model.pkl.
"""

import argparse
import os
import sys
import time
from typing import List, Tuple

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

# Expected feature column names matching feature_extraction.py
FEATURE_COLUMNS: List[str] = [
    "url_length",
    "num_dots",
    "has_at_symbol",
    "is_ip_address",
    "use_https",
    "ssl_valid",
    "domain_age_days",
    "num_redirects",
]
LABEL_COLUMN: str = "label"

# Default paths relative to project root
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA_PATH = os.path.join(BASE_DIR, "data", "phishing_dataset.csv")
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "app", "model", "model.pkl")


def load_and_validate_data(csv_path: str) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Load dataset from CSV and validate feature and label columns.
    """
    if not os.path.exists(csv_path):
        print(f"Error: Dataset not found at '{csv_path}'.", file=sys.stderr)
        print(
            f"Please place your CSV dataset at '{csv_path}' with the following columns:\n"
            f"  Features: {', '.join(FEATURE_COLUMNS)}\n"
            f"  Target:   {LABEL_COLUMN} (0 = safe, 1 = phishing)\n",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Loading dataset from: {csv_path}")
    df = pd.read_csv(csv_path)

    # Check for missing required columns
    missing_features = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_features:
        print(
            f"Error: Missing required feature columns in CSV: {missing_features}",
            file=sys.stderr,
        )
        sys.exit(1)

    if LABEL_COLUMN not in df.columns:
        print(
            f"Error: Missing target label column '{LABEL_COLUMN}' in CSV.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Handle missing values
    initial_count = len(df)
    df = df.dropna(subset=FEATURE_COLUMNS + [LABEL_COLUMN])
    dropped_count = initial_count - len(df)
    if dropped_count > 0:
        print(f"Dropped {dropped_count} rows containing missing/null values.")

    print(f"Loaded {len(df)} samples successfully.")
    print(f"Class distribution:\n{df[LABEL_COLUMN].value_counts().to_string()}\n")

    X = df[FEATURE_COLUMNS]
    y = df[LABEL_COLUMN].astype(int)
    return X, y


def train_and_evaluate(
    data_path: str = DEFAULT_DATA_PATH,
    model_output_path: str = DEFAULT_MODEL_PATH,
    test_size: float = 0.2,
    random_state: int = 42,
    n_estimators: int = 100,
) -> RandomForestClassifier:
    """
    Execute full training and evaluation pipeline:
    1. Load data
    2. Train/Test split
    3. Train RandomForestClassifier
    4. Print metrics (Accuracy, Precision, Recall, F1)
    5. Save model with joblib
    """
    X, y = load_and_validate_data(data_path)

    # Split dataset
    print(f"Splitting dataset (test_size={test_size}, random_state={random_state})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y if len(y.unique()) > 1 else None,
    )
    print(f"Train size: {len(X_train)}, Test size: {len(X_test)}")

    # Train model using all CPU cores (n_jobs=-1)
    print(f"\nTraining RandomForestClassifier (n_estimators={n_estimators}, n_jobs=-1 [all CPU cores])...")
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
    )

    start_time = time.time()
    model.fit(X_train, y_train)
    training_duration = time.time() - start_time
    print(f"Training completed in {training_duration:.2f} seconds ({training_duration / 60:.2f} minutes).")

    # Predict & evaluate on test set
    y_pred = model.predict(X_test)

    # Compute metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 50)
    print("             CONFUSION MATRIX                    ")
    print("=" * 50)
    print(f"  True Negatives  (Safe correctly identified):     {cm[0][0]:,}")
    print(f"  False Positives (Safe misclassified as Phishing): {cm[0][1]:,}")
    print(f"  False Negatives (Phishing misclassified as Safe): {cm[1][0]:,}")
    print(f"  True Positives  (Phishing correctly identified):  {cm[1][1]:,}")
    print("-" * 50)
    print(f"  Raw Confusion Matrix:\n{cm}")
    print("=" * 50)

    print("\n" + "=" * 50)
    print("           MODEL EVALUATION METRICS              ")
    print("=" * 50)
    print(f"  Training Time: {training_duration:.2f} seconds")
    print(f"  Accuracy:      {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"  Precision:     {precision:.4f}")
    print(f"  Recall:        {recall:.4f}")
    print(f"  F1 Score:      {f1:.4f}")
    print("=" * 50)

    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]))

    # Save model artifact
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    joblib.dump(model, model_output_path)
    print(f"Model successfully saved to: {model_output_path}\n")

    return model


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Phishing Detection Random Forest Model")
    parser.add_argument(
        "--data",
        type=str,
        default=DEFAULT_DATA_PATH,
        help=f"Path to CSV dataset (default: {DEFAULT_DATA_PATH})",
    )
    parser.add_argument(
        "--model-out",
        type=str,
        default=DEFAULT_MODEL_PATH,
        help=f"Path to save trained model artifact (default: {DEFAULT_MODEL_PATH})",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Proportion of the dataset to include in the test split (default: 0.2)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of trees in the Random Forest (default: 100)",
    )

    args = parser.parse_args()
    train_and_evaluate(
        data_path=args.data,
        model_output_path=args.model_out,
        test_size=args.test_size,
        n_estimators=args.n_estimators,
    )
