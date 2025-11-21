# Data Directory Documentation

This folder contains all datasets and supporting feature resources required for phishing URL detection experiments in this project. Due to GitHub file size constraints, the datasets are **not committed directly** to this repository.

Instead, all datasets required for running the notebooks are hosted in a cloud drive maintained by the project author.

---

## Download Datasets (Google Drive)

All necessary datasets are available here:

Google Drive Download Folder: https://drive.google.com/drive/folders/1VoKLITJYEXWPDyVM3TvdxAmw9dI5afbl?usp=drive_link

After downloading, unzip/place the files inside:
project_root/data/

---

## Folder Structure
data/
│
├── malicious_phish.csv # Kaggle dataset (raw input)
├── phishing_binary_dataset.csv # Kaggle dataset filtered to phishing / benign
├── df_650k_features.csv # Cached engineered features (generated once)
│
├── dataset_A_05_2020/ # Mendeley dataset - phishing detection benchmark
│ ├── dataset_A_05_2020_p1.csv
│ ├── dataset_A_05_2020_p2.csv
│ └── ... (multiple parts)
│
├── dataset_B_05_2020.csv # Mendeley dataset with enriched features
│
└── scripts/ # Provided with Mendeley dataset release
├── allbrands # Brand keyword list ✓ USED in feature extraction
├── content_features.py # Reference only ✘ not executed
├── external_features.py # Reference only ✘ not executed
├── feature_extractor.py # Reference only ✘ not executed
└── url_features.py # Reference only ✘ not executed


---

## Dataset Usage Summary

| File | Used For | Notes |
|------|----------|------|
| malicious_phish.csv | Primary dataset for ML model training | Large & imbalanced |
| phishing_binary_dataset.csv | Final processed training data | Used for XGBoost + SMOTE |
| df_650k_features.csv | Pre-computed features | Saves long feature extraction time |
| Mendeley datasets | Feature benchmarking | Balanced dataset enables feature selection |
| `scripts/allbrands` | Brand feature extraction | Improves phishing impersonation detection |