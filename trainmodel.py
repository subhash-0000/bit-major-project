import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# 📌 Step 1: Sample Training Data (You can expand this)
data = [
    ("Suspicious login attempt detected", "High"),
    ("Multiple failed login attempts", "Medium"),
    ("New device logged in from unknown location", "Medium"),
    ("System file modification detected", "Critical"),
    ("Firewall detected incoming attack", "Critical"),
    ("Malware detected and quarantined", "High"),
    ("User granted admin privileges", "Medium"),
    ("Regular log entry: System backup completed", "Low")
]

df = pd.DataFrame(data, columns=["message", "severity"])

# 📌 Step 2: Convert Severity to Numeric Labels
severity_mapping = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
df["severity"] = df["severity"].map(severity_mapping)

# 📌 Step 3: Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(df["message"], df["severity"], test_size=0.2, random_state=42)

# 📌 Step 4: TF-IDF Vectorization
vectorizer = TfidfVectorizer()
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# 📌 Step 5: Train Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_vec, y_train)

# 📌 Step 6: Save the Model & Vectorizer
joblib.dump(model, "alert_classifier.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")

print("✅ Model training complete! Saved as alert_classifier.pkl and tfidf_vectorizer.pkl")
