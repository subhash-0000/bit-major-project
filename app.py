from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
import joblib
import os
from datetime import datetime
import logging
from jira import JIRA
from sklearn.ensemble import RandomForestClassifier
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from sklearn.dummy import DummyClassifier

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
CONFIG = {
    'JIRA_SERVER': "https://subhashsrinivas36.atlassian.net/",
    'JIRA_USERNAME': "subhashsrinivas36@gmail.com",
    'JIRA_API_TOKEN': "ATATT3xFfGF0UpazxPmVZSf24og-4EJt03WeKS_GXoj3gFs7F_vtfUYMlkNeVcXpANujDbM84uut4YIVJ4I87KoDpX9VxyhgP1-yVWUOpabPgL-KyPA1P6VY5zZAp8Rh1OD6Zmw0fBoKRXsqz2naeDwCXr_vnsG8H1T0xfX6y4ZL7MvbPDDUiY8=CAAA8595",
    'JIRA_PROJECT_KEY': "SMS",
    'SLACK_BOT_TOKEN': "xoxb-8585975896066-8607931759536-8ayFLdc5jQA0uPbtPI7YSziT",
    'SLACK_CHANNEL_ID': "C08H97D5E7M"
}

# Configure PostgreSQL database
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:123@localhost:5432/alerts"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Jira ticket creation function
def create_jira_ticket(alert_message, severity):
    """
    Create a Jira ticket with the given alert and severity
    """
    try:
        # Map severity to Jira priority
        priority_mapping = {
            "Critical": "Highest",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low"
        }
        
        # Initialize Jira client
        jira = JIRA(
            server=CONFIG['JIRA_SERVER'],
            basic_auth=(CONFIG['JIRA_USERNAME'], CONFIG['JIRA_API_TOKEN'])
        )
        
        # Create issue dictionary without priority initially
        issue_dict = {
            'project': {'key': CONFIG['JIRA_PROJECT_KEY']},
            'summary': f"Security Alert: {alert_message[:50]}..." if len(alert_message) > 50 else alert_message,
            'description': f"""
            Alert Message: {alert_message}
            Severity: {severity}
            """,
            'issuetype': {'name': 'Task'},
        }
        
        # Create the ticket
        try:
            new_issue = jira.create_issue(fields=issue_dict)
            logger.info(f"Successfully created ticket: {new_issue.key}")
            
            # Try to set priority after creating the issue
            try:
                priority_name = priority_mapping.get(severity, "Medium")
                priority = jira.priorities()
                priority_id = None
                
                # Find the priority ID that matches our name
                for p in priority:
                    if p.name == priority_name:
                        priority_id = p.id
                        break
                
                if priority_id:
                    jira.issue(new_issue.key).update(fields={'priority': {'id': priority_id}})
                    logger.info(f"Successfully set priority to {priority_name}")
                else:
                    logger.warning(f"Priority {priority_name} not found, using default")
            except Exception as e:
                logger.warning(f"Could not set priority: {str(e)}")
            
            return new_issue.key
            
        except Exception as e:
            # Get detailed error information
            error_response = getattr(e, 'response', None)
            if error_response:
                error_text = error_response.text if hasattr(error_response, 'text') else str(error_response)
                logger.error(f"Detailed error creating ticket: {error_text}")
            else:
                logger.error(f"Error creating ticket: {str(e)}")
            return None
            
    except Exception as e:
        logger.error(f"Unexpected error in create_jira_ticket: {str(e)}")
        return None

# Initialize Slack client
def get_slack_client():
    try:
        client = WebClient(token=CONFIG['SLACK_BOT_TOKEN'])
        
        # Get channel info to verify we can access it
        try:
            response = client.conversations_info(channel=CONFIG['SLACK_CHANNEL_ID'])
            if not response["ok"]:
                logger.error(f"Failed to get channel info: {response['error']}")
                return None
                
            channel_info = response["channel"]
            logger.info(f"Found channel: {channel_info['name']} (ID: {CONFIG['SLACK_CHANNEL_ID']})")
            
            # Test posting a message to verify access
            try:
                test_message = "Security Alert Bot is online and ready to process alerts!"
                response = client.chat_postMessage(
                    channel=CONFIG['SLACK_CHANNEL_ID'],
                    text=test_message
                )
                if response["ok"]:
                    logger.info("Successfully tested Slack message posting")
                    return client
                else:
                    logger.error(f"Failed to post test message: {response['error']}")
                    return None
            except SlackApiError as e:
                logger.error(f"Error testing Slack connection: {e.response['error']}")
                return None
            
        except SlackApiError as e:
            logger.error(f"Error getting channel info: {e.response['error']}")
            return None
            
    except Exception as e:
        logger.error(f"Error initializing Slack client: {str(e)}")
        return None

# Initialize Jira client
def get_jira_client():
    try:
        jira = JIRA(
            server=CONFIG['JIRA_SERVER'],
            basic_auth=(CONFIG['JIRA_USERNAME'], CONFIG['JIRA_API_TOKEN'])
        )
        # Test the connection
        try:
            projects = jira.projects()
            logger.info(f"Successfully connected to Jira. Available projects: {', '.join([p.key for p in projects])}")
            # Check if we can access the specific project
            project = jira.project(CONFIG['JIRA_PROJECT_KEY'])
            logger.info(f"Successfully accessed project: {CONFIG['JIRA_PROJECT_KEY']}")
            return jira
        except Exception as e:
            logger.error(f"Error accessing Jira projects: {str(e)}")
            return None
    except Exception as e:
        logger.error(f"Error initializing Jira client: {str(e)}")
        return None

# Verify Jira connection and project access
try:
    jira = JIRA(
        server=CONFIG['JIRA_SERVER'],
        basic_auth=(CONFIG['JIRA_USERNAME'], CONFIG['JIRA_API_TOKEN'])
    )
    
    # Verify connection
    projects = jira.projects()
    available_projects = [p.key for p in projects]
    logger.info(f"Successfully connected to Jira. Available projects: {', '.join(available_projects)}")
    
    if CONFIG['JIRA_PROJECT_KEY'] not in available_projects:
        logger.error(f"Project {CONFIG['JIRA_PROJECT_KEY']} not found. Available projects: {', '.join(available_projects)}")
        raise ValueError(f"Project {CONFIG['JIRA_PROJECT_KEY']} not found")
        
    # Verify issue types
    issue_types = [t.name for t in jira.issue_types()]
    logger.info(f"Available issue types: {', '.join(issue_types)}")
    
    if 'Task' not in issue_types:
        logger.error("Task issue type not available in project")
        raise ValueError("Task issue type not available in project")
        
    # Verify priorities
    priorities = [p.name for p in jira.priorities()]
    logger.info(f"Available priorities: {', '.join(priorities)}")
    
except Exception as e:
    logger.error(f"Failed to verify Jira configuration: {str(e)}")
    raise

# Issue-specific recommendations
ISSUE_RECOMMENDATIONS = {
    "root_access": {
        "keywords": [
            "root access", "root login", "root detected", "sudo", "administrator access",
            "privileged access", "elevated privileges", "escalated privileges",
            "unauthorized admin", "admin credentials", "superuser"
        ],
        "severity": "HIGH",
        "actions": [
            "Immediately terminate the session",
            "Review recent system logs for suspicious activity",
            "Change all admin passwords",
            "Review and update sudoers file permissions"
        ],
        "jira_priority": "Critical",
        "slack_emoji": ":lock:"
    },
    "malware_detected": {
        "keywords": [
            "malware", "virus", "trojan", "malicious software", "ransomware",
            "malicious code", "malicious activity", "malware detected"
        ],
        "severity": "CRITICAL",
        "actions": [
            "Isolate affected systems",
            "Run full system scan",
            "Check for data exfiltration attempts",
            "Update antivirus definitions",
            "Review network traffic for malicious patterns"
        ],
        "jira_priority": "Blocker",
        "slack_emoji": ":warning:"
    },
    "unauthorized_access": {
        "keywords": [
            "unauthorized access", "unauthorized login", "failed login attempts",
            "brute force", "password guessing", "authentication failure"
        ],
        "severity": "MEDIUM",
        "actions": [
            "Block suspicious IP addresses",
            "Review authentication logs",
            "Implement rate limiting",
            "Review account lockout policies"
        ],
        "jira_priority": "High",
        "slack_emoji": ":no_entry:"
    },
    "data_exfiltration": {
        "keywords": [
            "data leak", "data exfiltration", "data theft", "sensitive data transfer",
            "unauthorized data transfer", "data breach"
        ],
        "severity": "CRITICAL",
        "actions": [
            "Block suspicious data transfers",
            "Review access controls",
            "Check for data encryption",
            "Review network egress rules",
            "Notify compliance team"
        ],
        "jira_priority": "Blocker",
        "slack_emoji": ":lock:"
    },
    "configuration_change": {
        "keywords": [
            "configuration change", "security settings modified", "firewall rules changed",
            "network settings modified", "security policy updated"
        ],
        "severity": "MEDIUM",
        "actions": [
            "Review configuration changes",
            "Verify change approvals",
            "Check for unauthorized modifications",
            "Restore previous configuration if unauthorized"
        ],
        "jira_priority": "High",
        "slack_emoji": ":gear:"
    }
}

# Function to process security alerts
def process_security_alert(alert_message):
    try:
        # Get clients
        slack_client = get_slack_client()
        jira_client = get_jira_client()
        
        if not slack_client or not jira_client:
            return False
            
        # Determine the issue type based on keywords
        issue_type = None
        for issue, config in ISSUE_RECOMMENDATIONS.items():
            if any(keyword in alert_message.lower() for keyword in config["keywords"]):
                issue_type = issue
                break
                
        if not issue_type:
            logger.warning("Could not determine issue type for alert")
            return False
            
        # Get issue configuration
        issue_config = ISSUE_RECOMMENDATIONS[issue_type]
        
        # Create Jira ticket
        try:
            jira_ticket_url = create_jira_ticket(
                f"Security Alert - {issue_type.replace('_', ' ').title()}",
                issue_config["jira_priority"]
            )
            if not jira_ticket_url:
                logger.error("Failed to create Jira ticket")
                return False
        except Exception as e:
            logger.error(f"Error creating Jira ticket: {str(e)}")
            return False
            
        # Format and send Slack message
        try:
            # Get recommendations from issue_config
            recommendations = "\n".join(f"{i+1}. {action}" for i, action in enumerate(issue_config['actions']))
            
            message = (
                f"{issue_config['slack_emoji']} *New Security Alert - {issue_config['severity']}*\n"
                f"*Message:* {alert_message}\n"
                f"*Recommended Actions:*\n"
                f"{recommendations}\n"
                f"*Jira Ticket:* <{jira_ticket_url}|View in Jira>\n"
                f"*Timestamp:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            response = slack_client.chat_postMessage(
                channel=CONFIG['SLACK_CHANNEL_ID'],
                text=message,
                username="Security Alert Bot",
                icon_emoji=":lock:"
            )
            if not response["ok"]:
                logger.error(f"Failed to post to Slack: {response['error']}")
                return False
                
        except SlackApiError as e:
            logger.error(f"Slack API error: {e.response['error']}")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Error processing security alert: {str(e)}")
        return False

# Severity mapping with recommendations
SEVERITY_MAPPING = {
    0: {
        "label": "Low",
        "recommendations": [
            "Monitor the situation for any changes",
            "Document the incident for future reference",
            "Notify relevant team members"
        ]
    },
    1: {
        "label": "Medium",
        "recommendations": [
            "Investigate the cause immediately",
            "Notify security team",
            "Implement temporary mitigation measures",
            "Document all findings"
        ]
    },
    2: {
        "label": "High",
        "recommendations": [
            "Activate incident response plan",
            "Notify senior management",
            "Isolate affected systems",
            "Gather forensic evidence",
            "Coordinate with security team"
        ]
    },
    3: {
        "label": "Critical",
        "recommendations": [
            "Activate emergency response plan",
            "Notify all stakeholders immediately",
            "Isolate affected systems immediately",
            "Contact law enforcement if necessary",
            "Gather all forensic evidence",
            "Prepare for media communication"
        ]
    }
}

# Check if model exists
MODEL_FILE = "alert_classifier.pkl"
VECTORIZER_FILE = "tfidf_vectorizer.pkl"

# Initialize model and vectorizer
model = None
vectorizer = None

try:
    # Load trained model and vectorizer
    logger.info(f"Loading model from {MODEL_FILE}")
    model = joblib.load(MODEL_FILE)
    logger.info(f"Model type: {type(model)}")
    logger.info(f"Loading vectorizer from {VECTORIZER_FILE}")
    vectorizer = joblib.load(VECTORIZER_FILE)
    logger.info(f"Vectorizer type: {type(vectorizer)}")
    logger.info("Model and vectorizer loaded successfully")
except Exception as e:
    logger.error(f"Error loading model/vectorizer: {str(e)}")
    logger.info("Using fallback model (always predicts Medium severity)")
    # Create a fallback model that always predicts Medium severity
    model = DummyClassifier(strategy="constant", constant=1)  # Medium severity
    vectorizer = None  # We won't use vectorizer in fallback mode

# Database Model
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)  
    severity = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    recommendations = db.Column(db.JSON, nullable=True)

# Create database tables
with app.app_context():
    try:
        # Drop existing tables if they exist
        db.drop_all()
        # Create new tables
        db.create_all()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {str(e)}")


# 1️⃣ Process Incoming Alert
@app.route('/process_alert', methods=['POST', 'GET'])
def process_alert():
    if request.method == 'GET':
        return '''
        <form method="post" onsubmit="return processForm(event)">
            <h2>Test Alert Processing</h2>
            <input type="text" name="message" id="message" placeholder="Enter alert message" required>
            <button type="submit">Submit</button>
            <div id="response"></div>
            <script>
                async function processForm(event) {
                    event.preventDefault();
                    const message = document.getElementById('message').value;
                    const responseDiv = document.getElementById('response');
                    
                    try {
                        const response = await fetch('/process_alert', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: `message=${encodeURIComponent(message)}`
                        });
                        
                        const data = await response.json();
                        if (data.error) {
                            responseDiv.innerHTML = `<pre>Error: ${data.error}</pre>`;
                        } else {
                            responseDiv.innerHTML = `
                                <h3>Alert Details</h3>
                                <p>Severity: ${data.severity}</p>
                                <p>Jira Ticket: ${data.jira_ticket || 'Failed to create Jira ticket'}</p>
                                
                                <h3>Immediate Actions</h3>
                                <ul>
                                    ${data.recommendations.immediate.map(item => `<li>${item}</li>`).join('')}
                                </ul>
                                
                                <h3>Long-term Actions</h3>
                                <ul>
                                    ${data.recommendations.long_term.map(item => `<li>${item}</li>`).join('')}
                                </ul>
                            `;
                        }
                    } catch (error) {
                        responseDiv.innerHTML = `<pre>Error: ${error}</pre>`;
                    }
                }
            </script>
        '''
    
    if request.method == 'POST':
        try:
            # Try to get message from JSON data
            alert_message = None
            
            # First try to get from form data
            if request.form and 'message' in request.form:
                alert_message = request.form['message']
            
            # If not found in form data, try JSON
            if alert_message is None:
                try:
                    data = request.get_json()
                    if data and 'message' in data:
                        alert_message = data['message']
                except:
                    pass
            
            if not alert_message:
                return jsonify({'error': 'No alert message provided'}), 400

            alert_message = alert_message.strip()
            if not alert_message:
                return jsonify({'error': 'Empty alert message'}), 400

            logger.info(f"Processing alert: {alert_message}")

            # If we have a model, use it to predict severity
            if model and vectorizer and isinstance(model, RandomForestClassifier):
                try:
                    # Vectorize the message
                    message_vec = vectorizer.transform([alert_message])
                    
                    # Predict severity
                    predicted_severity = model.predict(message_vec)[0]
                    severity = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}[predicted_severity]
                    logger.info(f"Predicted severity: {severity}")
                except Exception as e:
                    logger.error(f"Error predicting severity: {str(e)}")
                    # Fallback to Medium if prediction fails
                    severity = "Medium"
            else:
                # Fallback to Medium severity if model is not available
                severity = "Medium"
                logger.warning("Using fallback severity (Medium) as model is not available")

            # Create Jira ticket
            ticket_key = create_jira_ticket(alert_message, severity)
            if ticket_key:
                logger.info(f"Successfully created Jira ticket: {ticket_key}")
            else:
                logger.warning("Failed to create Jira ticket")

            # Get recommendations from ISSUE_RECOMMENDATIONS
            issue_type = None
            for issue, config in ISSUE_RECOMMENDATIONS.items():
                if any(keyword in alert_message.lower() for keyword in config["keywords"]):
                    issue_type = issue
                    break
            
            if issue_type:
                issue_config = ISSUE_RECOMMENDATIONS[issue_type]
                recommendations = {
                    "immediate": issue_config["actions"],
                    "long_term": []
                }
            else:
                recommendations = {
                    "immediate": [
                        "Review system logs for suspicious activity",
                        "Check for unauthorized access attempts",
                        "Review security policies and procedures",
                        "Consider implementing additional security measures"
                    ],
                    "long_term": []
                }

            # Send Slack notification
            try:
                # Get Slack client
                slack_client = get_slack_client()
                if not slack_client:
                    return jsonify({
                        'status': 'partial_success',
                        'message': 'Alert processed successfully but failed to send Slack notification',
                        'severity': severity,
                        'recommendations': recommendations,
                        'jira_ticket': ticket_key
                    }), 200

                # Format Slack message
                severity_str = severity if severity else "Unknown"
                alert_message_str = alert_message if alert_message else "No message available"
                ticket_key_str = ticket_key if ticket_key else "N/A"
                
                message = ":lock: *New Security Alert - " + severity_str + "*\n" + \
                          "*Message:* " + alert_message_str + "\n" + \
                          "*Recommended Actions:*\n" + \
                          "\n".join("• " + action for action in recommendations['immediate']) + "\n" + \
                          "*Jira Ticket:* <" + CONFIG['JIRA_SERVER'] + "/browse/" + ticket_key_str + "|View in Jira>\n" + \
                          "*Timestamp:* " + datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

                # Send message
                response = slack_client.chat_postMessage(
                    channel=CONFIG['SLACK_CHANNEL_ID'],
                    text=message,
                    username="Security Alert Bot",
                    icon_emoji=":lock:"
                )
                if not response["ok"]:
                    logger.error(f"Failed to post to Slack: {response['error']}")
                    return jsonify({
                        'status': 'partial_success',
                        'message': 'Alert processed successfully but failed to send Slack notification',
                        'severity': severity,
                        'recommendations': recommendations,
                        'jira_ticket': ticket_key
                    }), 200

            except SlackApiError as e:
                logger.error(f"Slack API error: {e.response['error']}")
                return jsonify({
                    'status': 'partial_success',
                    'message': 'Alert processed successfully but failed to send Slack notification',
                    'severity': severity,
                    'recommendations': recommendations,
                    'jira_ticket': ticket_key
                }), 200

            # Store in database
            new_alert = Alert(
                message=alert_message,
                severity=severity,
                recommendations=recommendations
            )
            db.session.add(new_alert)
            db.session.commit()

            return jsonify({
                'status': 'success',
                'message': 'Alert processed successfully',
                'severity': severity,
                'recommendations': recommendations,
                'jira_ticket': ticket_key
            }), 200

        except Exception as e:
            logger.error(f"Error processing alert: {str(e)}")
            return jsonify({'error': str(e)}), 500


# 2️⃣ Get All Stored Alerts
@app.route('/get_alerts', methods=['GET'])
def get_alerts():
    alerts = Alert.query.all()
    return jsonify([
        {
            "id": a.id, 
            "message": a.message, 
            "severity": a.severity,
            "recommendations": a.recommendations,
            "timestamp": a.timestamp
        } for a in alerts
    ])

# 3️⃣ Get Alerts by Severity
@app.route('/get_alerts/<severity>', methods=['GET'])
def get_alerts_by_severity(severity):
    severity = severity.capitalize()
    if severity not in [v["label"] for v in SEVERITY_MAPPING.values()]:
        return jsonify({"error": "Invalid severity. Use Low, Medium, High, or Critical"}), 400

    alerts = Alert.query.filter_by(severity=severity).all()
    return jsonify([
        {
            "id": a.id, 
            "message": a.message, 
            "severity": a.severity,
            "recommendations": a.recommendations,
            "timestamp": a.timestamp
        } for a in alerts
    ])

# 4️⃣ Delete All Alerts
@app.route('/delete_alerts', methods=['DELETE'])
def delete_alerts():
    try:
        db.session.query(Alert).delete()
        db.session.commit()
        return jsonify({"message": "All alerts deleted successfully."})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete alerts: {str(e)}")
        return jsonify({"error": f"Failed to delete alerts: {str(e)}"}), 500


# Run Flask App
if __name__ == '__main__':
    app.run(debug=True)
