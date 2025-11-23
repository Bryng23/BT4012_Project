import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler

df_features = pd.read_csv('df_650k_features.csv')

X = df_features.drop(columns=['url', 'label', 'https_token', 'nb_com', 'nb_slash', 'nb_subdomains', 'nb_www'], axis=1)
y = df_features['label']

# Train-test split with stratify
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Apply SMOTE to train set (2:1 ratio)
smote = SMOTE(sampling_strategy=0.5, random_state=42)
X_train_sm, y_train_sm = smote.fit_resample(X_train_scaled, y_train)

# Define and train XGBoost model
model = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",
    eval_metric="logloss",
    n_jobs=-1,
    random_state=42
)

model.fit(X_train_sm, y_train_sm)

# Export model, scaler, and threshold
with open("xgb_smote_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

with open("threshold.txt", "w") as f:
    f.write("0.4")