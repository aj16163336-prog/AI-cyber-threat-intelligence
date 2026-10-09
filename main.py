import pandas as pd

train_data = pd.read_csv("Data/UNSW_NB15_training-set.csv")

print("Training data size:", train_data.shape)
print("\nColumn names:")
print(train_data.columns.tolist())
print("\nFirst 3 rows:")
print(train_data.head(3))

print("\nMissing values (top 10 columns):")
print(train_data.isna().sum().sort_values(ascending=False).head(10))

print("\nBinary label counts:")
print(train_data["label"].value_counts())

print("\nAttack category counts:")
print(train_data["attack_cat"].value_counts(dropna=False))
test_data = pd.read_csv("Data/UNSW_NB15_testing-set.csv")
print("\nTesting data size:", test_data.shape)
print("Missing values in training data:", train_data.isna().sum().sum())
print("Missing values in testing data:", test_data.isna().sum().sum())
# Inputs for threat detection
X_train = train_data.drop(columns=["id", "attack_cat", "label"])
X_test = test_data.drop(columns=["id", "attack_cat", "label"])

# Normal (0) or attack (1)
y_train = train_data["label"]
y_test = test_data["label"]

# Attack category
y_attack_train = train_data["attack_cat"]
y_attack_test = test_data["attack_cat"]

print("\nTraining features:", X_train.shape)
print("Testing features:", X_test.shape)
print("Training detection labels:", y_train.shape)
print("Training attack categories:", y_attack_train.shape)
categorical_columns = X_train.select_dtypes(exclude="number").columns.tolist()
print("\nText columns to encode:", categorical_columns)
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

preprocessor = ColumnTransformer(
    transformers=[
        ("text", OneHotEncoder(handle_unknown="ignore"), categorical_columns)
    ],
    remainder="passthrough",
)

X_train_processed = preprocessor.fit_transform(X_train)
X_test_processed = preprocessor.transform(X_test)

print("\nProcessed training features:", X_train_processed.shape)
print("Processed testing features:", X_test_processed.shape)
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

detection_model = RandomForestClassifier(
    n_estimators=50,
    max_depth=12,
    random_state=42,
    n_jobs=-1,
)

detection_model.fit(X_train_processed, y_train)
detection_predictions = detection_model.predict(X_test_processed)

print("\nThreat detection accuracy:", accuracy_score(y_test, detection_predictions))
print("\nThreat detection report:")
print(classification_report(
    y_test,
    detection_predictions,
    target_names=["Normal", "Attack"],
))
attack_train_mask = y_train.to_numpy() == 1
attack_test_mask = y_test.to_numpy() == 1

attack_model = RandomForestClassifier(
    n_estimators=50,
    max_depth=12,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)

attack_model.fit(
    X_train_processed[attack_train_mask],
    y_attack_train[attack_train_mask],
)

attack_predictions = attack_model.predict(
    X_test_processed[attack_test_mask]
)

print(
    "\nAttack-type classification accuracy:",
    accuracy_score(
        y_attack_test[attack_test_mask],
        attack_predictions,
    ),
)
print("\nAttack-type classification report:")
print(classification_report(
    y_attack_test[attack_test_mask],
    attack_predictions,
    zero_division=0,
))
severity_scores = {
    "Analysis": 40,
    "Backdoor": 90,
    "DoS": 80,
    "Exploits": 90,
    "Fuzzers": 65,
    "Generic": 70,
    "Reconnaissance": 55,
    "Shellcode": 95,
    "Worms": 90,
}

predicted_detection = detection_model.predict(X_test_processed)
attack_probability = detection_model.predict_proba(X_test_processed)[:, 1]
detected_mask = predicted_detection == 1

category_probabilities = attack_model.predict_proba(
    X_test_processed[detected_mask]
)
category_indices = category_probabilities.argmax(axis=1)
predicted_category = attack_model.classes_[category_indices]
category_confidence = category_probabilities.max(axis=1)

base_severity = pd.Series(predicted_category).map(severity_scores).to_numpy()
risk_scores = (
    base_severity
    * attack_probability[detected_mask]
    * category_confidence
).round().astype(int)

risk_levels = pd.cut(
    risk_scores,
    bins=[-1, 39, 69, 89, 100],
    labels=["Low", "Medium", "High", "Critical"],
)

risk_report = pd.DataFrame({
    "id": test_data["id"].to_numpy()[detected_mask],
    "predicted_category": predicted_category,
    "risk_score": risk_scores,
    "risk_level": risk_levels,
})

print("\nSample risk report:")
print(risk_report.head(10))
risk_report.to_csv("threat_report.csv", index=False)
print("Full threat report saved as threat_report.csv")