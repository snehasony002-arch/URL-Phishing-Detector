import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
data = pd.read_csv("dataset/phishing_site_urls.csv")

# Convert labels
data['Label'] = data['Label'].map({
    'good': 0,
    'bad': 1
})

# Feature extraction
def extract_features(url):

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "banking",
        "signin",
        "confirm"
    ]

    return {
        "url_length": len(url),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "num_slashes": url.count('/'),
        "num_digits": sum(c.isdigit() for c in url),
        "has_https": 1 if "https" in url else 0,
        "has_at": 1 if "@" in url else 0,
        "has_ip": 1 if any(part.isdigit() for part in url.split('.')) else 0,
        "suspicious_word": 1 if any(word in url.lower() for word in suspicious_words) else 0
    }

# Create features
features = data['URL'].apply(extract_features)

X = pd.DataFrame(features.tolist())
y = data['Label']

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Train model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# Predict
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("Accuracy:", accuracy)

# Save model
joblib.dump(model, "model/phishing_model.pkl")

print("Model saved successfully!")