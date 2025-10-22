# Detailed Explanation of app.py

This document provides a comprehensive, section-by-section explanation of the `app.py` file, including all imports, configuration, models, API endpoints, and their purposes.

---

## 1. Imports

- **Flask, request, jsonify, render_template**: For building the web API and rendering responses.
- **Flask_SQLAlchemy**: ORM for interacting with the PostgreSQL database.
- **joblib**: For loading the trained machine learning model and vectorizer.
- **os**: Access environment variables and file paths.
- **datetime**: For timestamps.
- **logging**: For logging events and errors.
- **jira.JIRA**: For interacting with Jira (ticketing system).
- **sklearn.ensemble.RandomForestClassifier**: The ML model used for alert classification.
- **slack_sdk.WebClient, slack_sdk.errors.SlackApiError**: For sending notifications to Slack.
- **sklearn.dummy.DummyClassifier**: Used as a fallback ML model.
- **flask_cors.CORS**: Enables Cross-Origin Resource Sharing for the API.
- **google.generativeai**: For integrating with Gemini (Google's generative AI API).
- **json, re**: For parsing and handling JSON and regular expressions.
- **dotenv.load_dotenv**: Loads environment variables from a `.env` file.
- **sqlalchemy.text**: For raw SQL queries.
- **threading, time, random, requests**: For background tasks, simulations, and HTTP requests.

---

## 2. Configuration

- Loads environment variables for API keys, database credentials, and service tokens.
- Configures logging for debugging and error tracking.
- Sets up Flask app and enables CORS.
- Configures SQLAlchemy to connect to a PostgreSQL database.
- Loads and checks configuration for Jira, Slack, and Gemini.

---

## 3. External Service Clients

- **Jira**: Functions to create tickets, set priorities, and test connection.
- **Slack**: Functions to initialize the client, test authentication, check channel access, and send messages.
- **Gemini**: Configures the Gemini API for AI-based recommendations and classification.

---

## 4. Database Models

- **Alert**: Represents a security alert, with fields for message, severity, recommendations, Jira ticket, Slack notification status, and additional data.
- **SecurityEvent**: Represents a security event for SIEM, with similar fields and database indexes for efficient querying.

---

## 5. Static Mappings and Recommendations

- **PRIORITY_MAPPING**: Maps severity levels to Jira priorities.
- **ISSUE_RECOMMENDATIONS**: Maps alert types to recommended actions, Jira priorities, and Slack emojis.
- **SEVERITY_MAPPING**: Maps numeric severity to labels and recommendations.
- **FALLBACK_RECOMMENDATIONS**: Default recommendations if AI or model fails.

---

## 6. Machine Learning Model

- Loads a trained RandomForestClassifier and vectorizer for classifying alert severity.
- If loading fails, uses a DummyClassifier that always predicts 'Medium'.

---

## 7. Core Functions

- **create_jira_ticket**: Creates a Jira ticket for an alert, sets its priority, and returns the ticket key.
- **get_slack_client**: Initializes and tests the Slack client.
- **get_gemini_recommendations**: Uses Gemini API to generate recommendations, with fallback.
- **get_gemini_classification**: Uses Gemini API to classify severity and impact, with fallback.
- **index_security_event**: Saves a security event to the database.
- **search_security_events**: Searches security events in the database, with optional filters.

---

## 8. Main API Endpoints

- **/process_alert [POST]**: Main endpoint to process an alert. Classifies severity, generates recommendations, creates Jira ticket, sends Slack notification, stores in DB, and returns a summary.
- **/get_alerts [GET]**: Returns all stored alerts, optionally filtered by severity.
- **/get_alerts/<severity> [GET]**: Returns alerts of a specific severity.
- **/delete_alerts [DELETE]**: Deletes all alerts from the database.
- **/api/status [GET]**: Returns API status and version.
- **/api/db-check [GET]**: Checks database connection and tables.
- **/api/test-db [GET]**: Inserts a test alert to verify DB write access.
- **/api/test-slack [GET]**: Tests Slack integration and returns diagnostic info.
- **/api/search_alerts [POST]**: Searches security events by message content.
- **/api/siem/status [GET]**: Returns SIEM system status.
- **/api/siem/alerts [GET]**: Returns SIEM alerts with filtering options.
- **/api/siem/alerts/<int:alert_id> [GET]**: Returns a specific SIEM alert.
- **/api/siem/alerts/summary [GET]**: Returns a summary of SIEM alerts by severity and recent activity.
- **/api/threat-intelligence [GET]**: Returns simulated threat intelligence data.
- **/api/attack-simulation [POST]**: Starts or stops the threat simulation background process.
- **/api/geographic-threats [GET]**: Returns simulated geographic threat data.
- **/api/threat-stats [GET]**: Returns statistics and analytics on simulated threats.

---

## 9. Threat Intelligence Simulation

- Simulates threat intelligence and geographic threat data for dashboard/testing.
- Background thread generates random threats and updates global lists.
- Endpoints provide access to this simulated data for the frontend.

---

## 10. Utility and Admin Endpoints

- **/fix-database [GET]**: Drops and recreates all database tables (emergency use).
- **/migrate-database [GET]**: Adds missing columns to tables without dropping data.
- **/test [GET]**: Simple HTML test page to verify Flask is serving HTML.
- **/ [GET]**: Root endpoint returns API usage instructions.

---

## 11. Application Startup

- On startup, creates database tables if they do not exist.
- Runs the Flask app in debug mode.

---

# Summary Table: Key APIs and Their Purpose

| Endpoint                        | Method | Purpose                                                      |
|----------------------------------|--------|--------------------------------------------------------------|
| /process_alert                  | POST   | Process and classify a new alert, notify, and store it       |
| /get_alerts                     | GET    | Get all alerts (optionally filter by severity)               |
| /get_alerts/<severity>          | GET    | Get alerts of a specific severity                            |
| /delete_alerts                  | DELETE | Delete all alerts                                            |
| /api/status                     | GET    | Check API status                                             |
| /api/db-check                   | GET    | Check DB connection and tables                               |
| /api/test-db                    | GET    | Insert a test alert                                          |
| /api/test-slack                 | GET    | Test Slack integration                                       |
| /api/search_alerts              | POST   | Search security events by message                            |
| /api/siem/status                | GET    | Get SIEM system status                                       |
| /api/siem/alerts                | GET    | Get SIEM alerts with filters                                 |
| /api/siem/alerts/<alert_id>     | GET    | Get a specific SIEM alert                                    |
| /api/siem/alerts/summary        | GET    | Get SIEM alert summary                                       |
| /api/threat-intelligence        | GET    | Get simulated threat intelligence data                       |
| /api/attack-simulation          | POST   | Start/stop threat simulation                                 |
| /api/geographic-threats         | GET    | Get simulated geographic threat data                         |
| /api/threat-stats               | GET    | Get threat statistics and analytics                          |
| /fix-database                   | GET    | Drop and recreate all DB tables                              |
| /migrate-database               | GET    | Add missing columns to DB tables                             |
| /test                           | GET    | Simple HTML test page                                        |
| /                                | GET    | API usage instructions                                       |

---

# How the App Works (High Level)

1. **Receives security alerts** via API.
2. **Classifies** the alert using Gemini AI or a local ML model.
3. **Generates recommendations** for response.
4. **Creates a Jira ticket** and **sends a Slack notification**.
5. **Stores the alert and event** in the PostgreSQL database.
6. **Provides endpoints** for searching, filtering, and summarizing alerts and events.
7. **Simulates threat intelligence** for dashboard/testing purposes.

---

# Machine Learning Model Training (trainmodel_optimized.py)

This section explains the enhanced ML model training pipeline used to classify security alerts by severity.

## 12. Training Data Structure

The training dataset contains **240 carefully crafted examples** (60 per severity level) designed to teach the model to distinguish between security alert severities:

### Critical Severity Examples (60)
- **Active breaches**: "Ransomware detected encrypting production database", "Root access gained on domain controller"
- **Data theft**: "Sensitive customer data exfiltration detected", "Financial records accessed by unauthorized user"
- **System compromises**: "Multiple admin accounts compromised simultaneously", "Persistent backdoor installed on critical server"
- **IDS Critical alerts**: "Traffic involving blacklisted IP detected", "SYN flood attack with 500+ packets/60s"

### High Severity Examples (60)
- **Attack attempts**: "Brute force attack against admin portal", "SQL injection attempt blocked by WAF"
- **Malware detection**: "Malware quarantined on user workstation", "Suspicious PowerShell execution detected"
- **Network threats**: "Lateral movement detected across network segments", "Credential stuffing attack detected"
- **IDS High alerts**: "Port scan hitting 50+ unique ports", "RST flood with 120+ packets/60s"

### Medium Severity Examples (60)
- **Policy violations**: "User accessing resources outside normal pattern", "Unauthorized software installation detected"
- **Authentication issues**: "Multiple failed login attempts", "VPN connection from unusual location"
- **Configuration concerns**: "Security agent disabled on workstation", "Expired certificate in use"
- **IDS Medium alerts**: "SYN scan with 15+ packets/60s", "Port scan hitting 25 unique ports"

### Low Severity Examples (60)
- **Normal operations**: "Scheduled backup completed", "Routine security scan finished"
- **Maintenance activities**: "Software update deployed", "Standard user login during business hours"
- **Monitoring events**: "Health check passed", "System startup logged"
- **IDS Low alerts**: "Test alert from monitoring system", "Interface auto-detection completed"

## 13. Enhanced Feature Engineering

### Custom Security Feature Extractor
The `SecurityKeywordExtractor` class identifies security-specific patterns:

```python
security_keywords = {
    'critical_threats': ['ransomware', 'breach', 'compromised', 'backdoor', 'zero-day'],
    'attack_indicators': ['malware', 'attack', 'exploit', 'unauthorized', 'suspicious'],
    'network_events': ['scan', 'flood', 'intrusion', 'anomaly'],
    'authentication': ['login', 'password', 'credential', 'authentication']
}
```

### Network Pattern Recognition
Specialized regex patterns extract IDS-specific metrics:
- **Packet rates**: "SYNs=150 in 60s" → extracts 150/60 = 2.5 packets/second
- **Port scan detection**: "hitting 45 unique ports" → extracts port count: 45
- **IP blacklist**: "blacklisted IP detected" → boolean flag: True
- **Traffic volume**: "RST packets from IP (120 in 60s)" → extracts RST rate

### TF-IDF Enhancement
Advanced text vectorization with security-focused parameters:
- **N-gram range (1,3)**: Captures single words, phrases, and 3-word combinations
- **Max features 2000**: Prevents overfitting while capturing important patterns  
- **Min/Max document frequency**: Filters out too-rare and too-common words
- **Security stop words**: Removes generic words, keeps security-relevant terms

## 14. Ensemble Classification Pipeline

### Multi-Algorithm Voting Classifier
Combines predictions from 4 different algorithms for better accuracy:

1. **Random Forest (40% weight)**: 
   - 300 trees with controlled depth to prevent overfitting
   - Class balancing to handle severity distribution
   - Feature importance analysis for interpretability

2. **Support Vector Machine (30% weight)**:
   - RBF kernel for complex pattern recognition
   - Probability calibration for confidence scores
   - Gamma tuning for optimal decision boundaries

3. **Gradient Boosting (20% weight)**:
   - Sequential learning to correct classification errors
   - 100 estimators with learning rate 0.1
   - Max depth 6 to balance bias-variance trade-off

4. **Logistic Regression (10% weight)**:
   - Linear baseline for simple pattern recognition
   - L2 regularization to prevent overfitting
   - Fast training and prediction

### Feature Union Architecture
```
Raw Alert Text
├── TF-IDF Vectorizer (2000 features)
│   ├── Unigrams: individual words
│   ├── Bigrams: word pairs  
│   └── Trigrams: 3-word phrases
├── Security Keyword Extractor (20 features)
│   ├── Critical threat indicators
│   ├── Attack type classifications
│   ├── Network event patterns
│   └── Authentication markers
└── Network Pattern Extractor (10 features)
    ├── Packet rate calculations
    ├── Port scan metrics
    ├── IP blacklist flags
    └── Traffic volume indicators
```

## 15. Training and Validation Process

### Stratified Cross-Validation
- **5-fold stratified CV**: Ensures each severity level represented in all folds
- **Prevents data leakage**: Each fold maintains original class distribution
- **Robust evaluation**: Tests model performance across different data splits

### Hyperparameter Optimization
Grid search across key parameters:
- **TF-IDF max_features**: [1500, 2000, 2500] 
- **Random Forest n_estimators**: [200, 300, 400]
- **Random Forest max_depth**: [10, 15, 20]
- **SVM C parameter**: [0.1, 1.0, 10.0]
- **Gradient Boosting learning_rate**: [0.05, 0.1, 0.2]

### Performance Metrics
Comprehensive evaluation including:
- **Overall accuracy**: Percentage of correct predictions
- **Per-class precision**: True positives / (true positives + false positives)
- **Per-class recall**: True positives / (true positives + false negatives)
- **F1-score**: Harmonic mean of precision and recall
- **Confusion matrix**: Detailed breakdown of prediction errors
- **Cross-validation scores**: Consistency across different data splits

## 16. Model Integration with Main Application

### Loading Mechanism
```python
# In app.py - Model initialization
try:
    model = joblib.load("alert_classifier_optimized.pkl")
    vectorizer = joblib.load("tfidf_vectorizer_optimized.pkl")  
    feature_extractor = joblib.load("feature_pipeline_optimized.pkl")
    logger.info("Enhanced ML model loaded successfully")
except Exception as e:
    logger.error(f"ML model loading failed: {e}")
    # Falls back to DummyClassifier (always predicts Medium)
    model = DummyClassifier(strategy="constant", constant=1)
```

### Classification Pipeline
```python
# In process_alert() function
def classify_with_ml_model(alert_message):
    try:
        # Transform text using the same pipeline as training
        features = feature_extractor.transform([alert_message])
        
        # Get prediction and confidence
        prediction = model.predict(features)[0]
        probabilities = model.predict_proba(features)[0]
        confidence = max(probabilities)
        
        # Map numeric prediction to severity label
        severity_map = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
        severity = severity_map[prediction]
        
        logger.info(f"ML Classification: {severity} (confidence: {confidence:.2f})")
        return severity, confidence
        
    except Exception as e:
        logger.error(f"ML classification failed: {e}")
        return "Medium", 0.5  # Fallback to medium severity
```

### Multi-Classification Strategy
The main app uses a **hierarchical classification approach**:

1. **Primary**: Gemini AI classification (if API available)
2. **Secondary**: Enhanced ML model (if Gemini fails)  
3. **Fallback**: Simple rule-based classification
4. **Default**: Medium severity (if all methods fail)

This ensures **high availability** and **accurate classification** even when external services are unavailable.

## 17. Model Performance and Accuracy

### Target Performance Metrics
- **Overall Accuracy**: 70%+ (significantly improved from baseline 37%)
- **Critical Alert Recall**: 85%+ (crucial for security - cannot miss critical threats)
- **False Positive Rate**: <15% (minimize alert fatigue)
- **Cross-Validation Consistency**: <10% standard deviation across folds

### Expected Improvements Over Baseline
1. **Better Critical Detection**: Enhanced keyword patterns specifically target critical threats
2. **IDS Alert Handling**: Custom extractors properly parse network monitoring alerts  
3. **Reduced Overfitting**: Ensemble methods and regularization prevent memorization
4. **Consistent Performance**: Stratified validation ensures reliable results across different data distributions

### Production Monitoring
The model includes built-in monitoring capabilities:
- **Confidence scoring**: Each prediction includes confidence level
- **Feature importance**: Track which patterns drive classifications
- **Prediction logging**: All classifications logged for analysis and retraining
- **Performance drift detection**: Monitor accuracy over time to detect degradation

---

If you need a line-by-line or function-by-function breakdown, or want to know about a specific section in more detail, let me know!
