from flask import Flask, request, jsonify, render_template_string, render_template
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
from flask_cors import CORS
import google.generativeai as genai
import json
import re
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # More explicit CORS configuration

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
CONFIG = {
    'JIRA_SERVER': os.getenv('JIRA_SERVER', ""),
    'JIRA_USERNAME': os.getenv('JIRA_USERNAME', ""),
    'JIRA_API_TOKEN': os.getenv('JIRA_API_TOKEN', ""),
    'JIRA_PROJECT_KEY': os.getenv('JIRA_PROJECT_KEY', "SMS"),
    'SLACK_BOT_TOKEN': os.getenv('SLACK_BOT_TOKEN', ""),
    'SLACK_CHANNEL_ID': os.getenv('SLACK_CHANNEL_ID', ""),
    "GEMINI_API_KEY": os.getenv('GEMINI_API_KEY', "")
}

# Add this after your CONFIG definition
logger.info("Checking API configurations...")
missing_configs = []
for key, value in CONFIG.items():
    if not value:
        missing_configs.append(key)
        logger.error(f"Missing or empty configuration for {key}")

if missing_configs:
    logger.warning(f"The following configurations are missing or empty: {', '.join(missing_configs)}")
else:
    logger.info("All configurations present")

# Initialize Gemini (add this after your CONFIG definition)
try:
    genai.configure(api_key=CONFIG["GEMINI_API_KEY"])
    logger.info("Gemini API configured successfully")
except Exception as e:
    logger.error(f"Error configuring Gemini API: {str(e)}")

# Configure PostgreSQL database
db_username = os.getenv('DB_USERNAME', 'postgres')
db_password = os.getenv('DB_PASSWORD', '123')
db_host = os.getenv('DB_HOST', 'localhost')
db_name = os.getenv('DB_NAME', 'alerts')

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_username}:{db_password}@{db_host}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the priority mapping as a proper variable
PRIORITY_MAPPING = {
    "Critical": "Highest",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low"
}

# Initialize Jira client
def create_jira_ticket(alert_message, severity):
    try:
        # Define the priority mapping as a proper variable
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
    jira_ticket_id = db.Column(db.String(50), nullable=True)
    slack_notification_sent = db.Column(db.Boolean, default=False)
    additional_data = db.Column(db.JSON, nullable=True)  # Add this column for impact, reasoning, etc.
    
    def __repr__(self):
        return f"<Alert id={self.id}, severity={self.severity}>"

# Add a fallback mechanism in case Gemini API fails

# Create a fallback recommendations dictionary
FALLBACK_RECOMMENDATIONS = {
    "Critical": {
        "immediate": [
            "Isolate affected systems from the network",
            "Activate incident response team",
            "Preserve forensic evidence"
        ],
        "long_term": [
            "Conduct thorough security assessment",
            "Implement additional monitoring controls",
            "Update security policies and procedures"
        ]
    },
    "High": {
        "immediate": [
            "Investigate suspicious activity",
            "Monitor affected systems closely",
            "Review related security logs"
        ],
        "long_term": [
            "Enhance security controls in affected area",
            "Provide additional user training",
            "Review and update detection capabilities"
        ]
    },
    "Medium": {
        "immediate": [
            "Verify the alert details",
            "Document the incident",
            "Monitor for escalation"
        ],
        "long_term": [
            "Review security configurations",
            "Consider additional security controls",
            "Update monitoring rules"
        ]
    },
    "Low": {
        "immediate": [
            "Log the event",
            "No immediate action required",
            "Include in regular security review"
        ],
        "long_term": [
            "Review if pattern emerges",
            "Consider in next security assessment",
            "Update baseline if appropriate"
        ]
    },
    "default": {
        "immediate": ["Investigate the alert", "Document findings"],
        "long_term": ["Review security controls", "Update procedures if needed"]
    }
}

# Update the get_gemini_recommendations function to use fallback
def get_gemini_recommendations(alert_message, severity):
    """Generate security recommendations using Gemini API"""
    try:
        if not CONFIG.get("GEMINI_API_KEY"):
            logger.warning("No Gemini API key provided, using fallback recommendations")
            return ISSUE_RECOMMENDATIONS.get("default", {"immediate": [], "long_term": []})
        
        # Create the prompt for Gemini
        prompt = f"""
        As a cybersecurity expert, provide actionable recommendations for this security alert:
        
        Alert: {alert_message}
        Severity: {severity}
        
        Provide recommendations in the following JSON format:
        {{
            "immediate": ["Action 1", "Action 2", "Action 3"],
            "long_term": ["Strategy 1", "Strategy 2", "Strategy 3"] 
        }}
        
        Keep recommendations brief but specific.
        For immediate actions, focus on containment and investigation steps.
        For long-term actions, focus on prevention and risk reduction.
        
        Only include the JSON in your response, nothing else.
        """
        
        # Generate recommendations with Gemini
        model = genai.GenerativeModel('gemini-1.5-pro')
        response = model.generate_content(prompt)
        
        # Parse the response to extract JSON
        json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
        if json_match:
            recommendations = json.loads(json_match.group(0))
            logger.info(f"Successfully generated recommendations with Gemini")
            return recommendations
        else:
            logger.warning("Couldn't parse Gemini response as JSON")
            return {"immediate": [], "long_term": []}
            
    except Exception as e:
        logger.error(f"Error generating recommendations with Gemini: {str(e)}")
        # Use fallback recommendations based on severity
        return FALLBACK_RECOMMENDATIONS.get(severity, FALLBACK_RECOMMENDATIONS["default"])

# Function to get severity classification from Gemini
def get_gemini_classification(alert_message):
    """Use Gemini API to classify the severity and impact of an alert"""
    try:
        if not CONFIG.get("GEMINI_API_KEY"):
            logger.warning("No Gemini API key provided, using fallback severity")
            return {"severity": "Medium", "impact": "Unknown"}
        
        # Create the prompt for Gemini
        prompt = f"""
        As a cybersecurity expert, analyze this security alert and classify its severity and impact:
        
        Alert: {alert_message}
        
        Provide your assessment in the following JSON format:
        {{
            "severity": "Critical|High|Medium|Low",
            "impact": "A brief description of the potential impact (1-2 sentences)",
            "reasoning": "Brief explanation for your classification (1-2 sentences)"
        }}
        
        Only include the JSON in your response, nothing else.
        """
        
        # Generate classification with Gemini
        model = genai.GenerativeModel('gemini-1.5-pro')
        response = model.generate_content(prompt)
        
        # Parse the response to extract JSON
        json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
        if json_match:
            classification = json.loads(json_match.group(0))
            logger.info(f"Successfully generated classification with Gemini")
            
            # Ensure severity is one of our expected values
            if classification.get("severity") not in ["Critical", "High", "Medium", "Low"]:
                classification["severity"] = "Medium"  # Default to Medium if unexpected value
                
            return classification
        else:
            logger.warning("Couldn't parse Gemini response as JSON")
            return {"severity": "Medium", "impact": "Unknown", "reasoning": "Classification failed"}
            
    except Exception as e:
        logger.error(f"Error generating classification with Gemini: {str(e)}")
        return {"severity": "Medium", "impact": "Unknown", "reasoning": f"Error: {str(e)}"}

# Add endpoint to get available classification methods
@app.route('/api/classification-methods', methods=['GET'])
def get_classification_methods():
    """Return available classification methods"""
    methods = [
        {"id": "model", "name": "Local ML Model", "description": "Uses the trained machine learning model"},
        {"id": "gemini", "name": "Gemini AI", "description": "Uses Google's Gemini AI for intelligent classification"}
    ]
    return jsonify(methods)

# 1️⃣ Process Incoming Alert
@app.route('/process_alert', methods=['POST'])
def process_alert():
    # Start a database transaction
    db_transaction = db.session.begin_nested()
    
    try:
        data = request.json
        if not data or 'message' not in data:
            return jsonify({"error": "Missing required field: message"}), 400
            
        alert_message = data['message']
        alert_message = alert_message.strip()
        if not alert_message:
            return jsonify({'error': 'Empty alert message'}), 400

        # Get classification method from request
        classification_method = data.get('classification_method', 'model')  # Default to model
        logger.info(f"Processing alert using {classification_method} method: {alert_message}")

        impact = None
        reasoning = None

        # If we use Gemini for classification
        if classification_method == 'gemini':
            try:
                # Get classification from Gemini
                classification = get_gemini_classification(alert_message)
                severity = classification.get("severity", "Medium")
                impact = classification.get("impact", "Unknown impact")
                reasoning = classification.get("reasoning", "No reasoning provided")
                logger.info(f"Gemini classification: {severity}, Impact: {impact}")
                
                # Use Gemini for recommendations too
                recommendations = get_gemini_recommendations(alert_message, severity)
                logger.info(f"Generated Gemini recommendations: {recommendations}")
            except Exception as e:
                logger.error(f"Error using Gemini for classification: {str(e)}")
                # Fallback to Medium if Gemini fails
                severity = "Medium"
                impact = "Classification failed"
                reasoning = f"Error: {str(e)}"
                # Fallback recommendations
                recommendations = FALLBACK_RECOMMENDATIONS.get(severity, FALLBACK_RECOMMENDATIONS["default"])
        # If we use our model
        elif model and vectorizer and isinstance(model, RandomForestClassifier):
            try:
                # Vectorize the message
                message_vec = vectorizer.transform([alert_message])
                
                # Predict severity
                predicted_severity = model.predict(message_vec)[0]
                severity = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}[predicted_severity]
                logger.info(f"Predicted severity: {severity}")
                
                # Use static recommendations based on severity for local model
                severity_index = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}.get(severity, 1)
                severity_info = SEVERITY_MAPPING[severity_index]
                
                # Format recommendations in the same structure as Gemini returns
                immediate_actions = severity_info["recommendations"]
                recommendations = {
                    "immediate": immediate_actions,
                    "long_term": [
                        "Review security policies related to this type of alert",
                        "Update detection and response procedures if needed",
                        "Consider additional training for relevant teams"
                    ]
                }
                logger.info(f"Using local model recommendations for severity: {severity}")
            except Exception as e:
                logger.error(f"Error predicting severity: {str(e)}")
                # Fallback to Medium if prediction fails
                severity = "Medium"
                # Use fallback recommendations
                recommendations = FALLBACK_RECOMMENDATIONS.get(severity, FALLBACK_RECOMMENDATIONS["default"])
        else:
            # Fallback to Medium severity if model is not available
            severity = "Medium"
            logger.warning("Using fallback severity (Medium) as model is not available")
            # Use fallback recommendations
            recommendations = FALLBACK_RECOMMENDATIONS.get(severity, FALLBACK_RECOMMENDATIONS["default"])

        # Create Jira ticket
        logger.info("Attempting to create Jira ticket...")
        ticket_key = create_jira_ticket(alert_message, severity)
        if (ticket_key):
            if ticket_key.startswith("ERROR:"):
                logger.error(f"Jira ticket creation failed: {ticket_key}")
            else:
                logger.info(f"Successfully created Jira ticket: {ticket_key}")
        else:
            logger.warning("No Jira ticket key was returned")

        # Send Slack notification
        logger.info("Attempting to send Slack notification...")
        slack_success = False  # Default to False
        try:
            # Get Slack client
            slack_client = get_slack_client()
            if not slack_client:
                logger.warning("Failed to initialize Slack client")
            else:
                # Format Slack message
                severity_str = severity if severity else "Unknown"
                alert_message_str = alert_message if alert_message else "No message available"
                ticket_key_str = ticket_key if ticket_key else "N/A"
                
                # Add impact to Slack message if available
                impact_text = f"\n*Impact:* {impact}" if impact else ""
                
                message = ":lock: *New Security Alert - " + severity_str + "*\n" + \
                          "*Message:* " + alert_message_str + \
                          impact_text + "\n" + \
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
                if response["ok"]:
                    slack_success = True
                    logger.info("Successfully sent Slack notification")
                else:
                    logger.error(f"Failed to post to Slack: {response['error']}")
        except Exception as e:
            logger.error(f"Error sending Slack notification: {str(e)}")
            # Keep slack_success as False

        # Database operations within separate try-except
        try:
            logger.info(f"Creating new alert in database")
            
            # Create additional_data field to store impact and reasoning
            additional_data = {}
            if impact:
                additional_data["impact"] = impact
            if reasoning:
                additional_data["reasoning"] = reasoning
            
            # Store classification method used
            additional_data["classification_method"] = classification_method
            
            new_alert = Alert(
                message=alert_message,
                severity=severity,
                recommendations=recommendations,
                jira_ticket_id=ticket_key,
                slack_notification_sent=slack_success,
                additional_data=additional_data  # Store the additional data
            )
            db.session.add(new_alert)
            db.session.flush()  # Flush without committing to get ID
            alert_id = new_alert.id
            logger.info(f"Alert created with ID: {alert_id}")
        except Exception as db_error:
            logger.error(f"Database error: {str(db_error)}")
            db_transaction.rollback()
            return jsonify({'error': f"Database error: {str(db_error)}"}), 500
        
        # If we got here, commit the transaction
        db_transaction.commit()
        db.session.commit()
        
        # Return response
        response_data = {
            "status": "success",
            "severity": severity,
            "jira_ticket": ticket_key,
            "slack_notification_sent": slack_success,
            "recommendations": recommendations,
            'alert_id': new_alert.id,
            'timestamp': new_alert.timestamp.isoformat(),
            'classification_method': classification_method
        }
        
        # Add impact and reasoning if available
        if impact:
            response_data["impact"] = impact
        if reasoning:
            response_data["reasoning"] = reasoning
            
        return jsonify(response_data)
        
    except Exception as e:
        # Ensure transaction is rolled back on any error
        db_transaction.rollback()
        logger.error(f"Error processing alert: {str(e)}")
        return jsonify({'error': str(e)}), 500

# 2️⃣ Get All Stored Alerts
@app.route('/get_alerts', methods=['GET'])
def get_alerts():
    try:
        # First, check if additional_data column exists and add it if missing
        try:
            with db.engine.connect() as conn:
                # Check if column exists
                check_col = "SELECT column_name FROM information_schema.columns WHERE table_name='alert' AND column_name='additional_data'"
                result = conn.execute(check_col)
                column_exists = result.fetchone() is not None
                
                if not column_exists:
                    # Add column if it doesn't exist
                    conn.execute("ALTER TABLE alert ADD COLUMN additional_data JSONB")
                    logger.info("Successfully added additional_data column")
        except Exception as e:
            logger.error(f"Failed to check/add additional_data column: {str(e)}")
        
        # Now proceed with query
        severity = request.args.get('severity')
        if (severity):
            severity = severity.capitalize()
            if severity not in [v["label"] for v in SEVERITY_MAPPING.values()]:
                return jsonify({"error": "Invalid severity. Use Low, Medium, High, or Critical"}), 400
            alerts = Alert.query.filter_by(severity=severity).all()
        else:
            alerts = Alert.query.all()
            
        # Use a more defensive approach when serializing alerts
        result = []
        for a in alerts:
            alert_dict = {
                "id": a.id, 
                "message": a.message, 
                "severity": a.severity,
                "recommendations": a.recommendations if (a.recommendations and isinstance(a.recommendations, dict)) 
                                 else {"immediate": [], "long_term": []},
                "timestamp": a.timestamp.isoformat() if hasattr(a.timestamp, 'isoformat') else str(a.timestamp),
                "jira_ticket_id": getattr(a, 'jira_ticket_id', None),
                "slack_notification_sent": bool(getattr(a, 'slack_notification_sent', False))
            }
            
            # Only add additional_data if it exists
            if hasattr(a, 'additional_data') and a.additional_data is not None:
                alert_dict["additional_data"] = a.additional_data
            else:
                alert_dict["additional_data"] = {}
                
            result.append(alert_dict)
            
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        return jsonify({"error": str(e)}), 500

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
@app.route('/delete_alerts', methods=['DELETE'])  # Changed [] to () for methods
def delete_alerts():
    try:
        db.session.query(Alert).delete()
        db.session.commit()
        return jsonify({"message": "All alerts deleted successfully."})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete alerts: {str(e)}")
        return jsonify({"error": f"Failed to delete alerts: {str(e)}"}), 500

# Replace these routes with API-only routes
@app.route('/')
def index():
    """Redirect root to API status endpoint"""
    return jsonify({
        "message": "This is a REST API server. Please use the React frontend to interact with the API.",
        "endpoints": {
            "GET /api/status": "Check API status",
            "GET /get_alerts": "Get all alerts",
            "GET /get_alerts?severity=High": "Filter alerts by severity",
            "POST /process_alert": "Process a new alert",
            "DELETE /delete_alerts": "Delete all alerts"
        }
    })

# Add this route before if __name__ == '__main__':
@app.route('/test')
def test_page():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Page</title>
    </head>
    <body>
        <h1>Test Page</h1>
        <p>If you can see this, Flask is serving HTML correctly.</p>
    </body>
    </html>
    """

# Add these diagnostic endpoints before the if __name__ == '__main__' block:
@app.route('/api/db-check', methods=['GET'])
def db_check():
    """Check database connection and tables"""
    try:
        # Check if we can connect to database
        result = db.session.execute('SELECT 1').scalar()
        # Check if Alert table exists and get count
        alert_count = db.session.query(Alert).count()
        # Get table info
        tables = []
        with db.engine.connect() as conn:
            result = conn.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public'")
            tables = [row[0] for row in result]
        return jsonify({
            "connection": "success",
            "tables": tables,
            "alert_count": alert_count,
            "db_uri": app.config["SQLALCHEMY_DATABASE_URI"].replace("postgres:123", "postgres:***")
        }), 200
    except Exception as e:
        return jsonify({
            "connection": "error",
            "error": str(e),
            "db_uri": app.config["SQLALCHEMY_DATABASE_URI"].replace("postgres:123", "postgres:***")
        }), 500

@app.route('/api/test-db', methods=['GET'])
def test_db():
    """Test database insertion"""
    try:
        # Create a simple test alert
        test_alert = Alert(
            message="Test alert from diagnostic endpoint",
            severity="Low",
            recommendations={"immediate": ["Test action"]}
        )
        # Add and commit
        db.session.add(test_alert)
        db.session.commit()
        return jsonify({
            "success": True,
            "message": "Test alert created successfully",
            "alert_id": test_alert.id
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/debug', methods=['GET'])
def debug_response():
    """Return a debug response with all expected fields"""
    sample_alert = {
        'status': 'success',
        'message': 'This is a test alert',
        'severity': 'High',
        'recommendations': {
            'immediate': ['Check system logs', 'Isolate affected systems'],
            'long_term': ['Implement additional monitoring', 'Review security policy']
        },
        'jira_ticket': 'SMS-123',
        'slack_notification_sent': True,
        'alert_id': 999,
        'timestamp': datetime.utcnow().isoformat()
    }
    return jsonify(sample_alert)

# Move this route above the if __name__ == '__main__': block
@app.route('/api/status', methods=['GET'])
def api_status():
    """Simple endpoint to check if API is running"""
    return jsonify({
        "status": "online",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    })

# Add this just before your if __name__ == '__main__': block
@app.route('/fix-database', methods=['GET'])
def fix_database():
    """Emergency endpoint to recreate database tables"""
    try:
        # Drop all tables and recreate them
        with app.app_context():
            db.drop_all()
            db.create_all()
        return jsonify({
            "success": True,
            "message": "Database tables have been recreated"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/migrate-database', methods=['GET'])
def migrate_database():
    """Add missing columns without recreating tables"""
    try:
        with db.engine.connect() as conn:
            # Check if additional_data column exists
            try:
                check_col = "SELECT column_name FROM information_schema.columns WHERE table_name='alert' AND column_name='additional_data'"
                result = conn.execute(check_col)
                column_exists = result.fetchone() is not None
                
                if not column_exists:
                    # Add additional_data column if it doesn't exist
                    conn.execute("ALTER TABLE alert ADD COLUMN additional_data JSONB")
                    return jsonify({
                        "success": True,
                        "message": "Added missing 'additional_data' column to Alert table"
                    }), 200
                else:
                    return jsonify({
                        "success": True,
                        "message": "No migration needed, column already exists"
                    }), 200
            except Exception as e:
                # If the check fails, try a more direct approach
                try:
                    conn.execute("ALTER TABLE alert ADD COLUMN IF NOT EXISTS additional_data JSONB")
                    return jsonify({
                        "success": True,
                        "message": "Added missing 'additional_data' column to Alert table (fallback method)"
                    }), 200
                except Exception as inner_e:
                    return jsonify({
                        "success": False,
                        "error": f"Failed to add column: {str(inner_e)}"
                    }), 500
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# Keep this part inside if __name__ == '__main__':
if __name__ == '__main__':
    with app.app_context():
        try:
            # Create tables if they don't exist
            db.create_all()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database tables: {str(e)}")
    
    app.run(debug=True)
