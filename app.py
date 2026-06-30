from flask import Flask, render_template, request
import joblib
import pandas as pd
from datetime import datetime

app = Flask(__name__)

# Load trained model
model = joblib.load("model/phishing_model.pkl")

# Store recent scans
history = []

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

@app.route('/')
def home():
    return render_template(
        'index.html',
        history=[]
    )

@app.route('/predict', methods=['POST'])
def predict():

    url = request.form['url']

    scan_time = datetime.now().strftime(
        "%d-%m-%Y %I:%M %p"
    )

    features = extract_features(url)

    X = pd.DataFrame([features])

    prediction = model.predict(X)[0]

    # ----------------------------
    # Risk Score Logic
    # ----------------------------

    risk_score = 15

    medium_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "signin"
    ]

    if prediction == 1:
        risk_score = 90

    elif any(word in url.lower() for word in medium_keywords):
        risk_score = 50

    else:
        risk_score = 15

    # ----------------------------
    # Risk Level
    # ----------------------------

    if risk_score <= 30:
        risk_level = "LOW"
        risk_color = "#22c55e"

    elif risk_score <= 70:
        risk_level = "MEDIUM"
        risk_color = "#facc15"

    else:
        risk_level = "HIGH"
        risk_color = "#ef4444"

    # Prediction Result

    if prediction == 1:
        result = "danger"
        status = "Phishing"
    else:
        result = "safe"
        status = "Safe"

    # Save History

    history.append({
        "url": url,
        "status": status
    })

    if len(history) > 5:
        history.pop(0)

    return render_template(
        'index.html',
        prediction=result,
        scan_time=scan_time,
        history=history,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_color=risk_color
    )

if __name__ == "__main__":
    app.run(debug=True)