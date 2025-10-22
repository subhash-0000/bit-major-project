import pandas as pd
import joblib
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, VotingClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin

# 📌 Custom Feature Extractors for Better Classification
class SecurityKeywordExtractor(BaseEstimator, TransformerMixin):
    """Extract security-specific features from alert text"""
    
    def __init__(self):
        # Enhanced keyword indicators with more specific terms
        self.critical_keywords = [
            'ransomware', 'breach', 'compromised', 'backdoor', 'zero-day', 'apt', 'exfiltration',
            'domain controller', 'root access', 'admin compromise', 'data theft', 'cryptomining',
            'command and control', 'c2', 'persistence', 'lateral movement', 'privilege escalation',
            'remote code execution', 'buffer overflow', 'nation-state', 'insider threat',
            'cryptocurrency', 'keylogger', 'rootkit', 'bootkit', 'fileless', 'living off the land'
        ]
        
        self.high_keywords = [
            'malware', 'virus', 'trojan', 'exploit', 'vulnerability', 'attack', 'suspicious',
            'unauthorized', 'brute force', 'sql injection', 'xss', 'phishing', 'credential',
            'powershell', 'unusual', 'anomalous', 'failed authentication', 'port scan',
            'credential stuffing', 'password spraying', 'enumeration', 'reconnaissance',
            'dns tunneling', 'data leakage', 'privilege abuse', 'lateral move', 'escalation'
        ]
        
        self.medium_keywords = [
            'failed login', 'multiple attempts', 'unknown location', 'unusual time',
            'policy violation', 'expired certificate', 'suspicious download', 'usb device',
            'geolocation', 'new device', 'password reset', 'file access', 'account lockout',
            'session timeout', 'weak password', 'configuration change', 'service restart'
        ]
        
        self.low_keywords = [
            'backup', 'maintenance', 'update', 'scan completed', 'training', 'routine',
            'scheduled', 'normal', 'standard', 'regular', 'authorized', 'startup', 'logout',
            'health check', 'performance', 'monitoring', 'patch', 'compliance', 'baseline'
        ]
        
        # Enhanced network/IDS specific patterns with severity weights
        self.network_patterns = {
            r'(\d+)\s+in\s+(\d+)s': 'rate_pattern',  # "50 SYNs in 60s"
            r'(\d+)\s+unique\s+ports': 'port_scan_pattern',  # "25 unique ports"
            r'\d+\.\d+\.\d+\.\d+': 'ip_pattern',  # IP addresses
            r'port\s+\d+': 'port_pattern',  # "port 445"
            r'flags?\s+[A-Z]+': 'tcp_flags_pattern',  # "flags S"
            r'blacklist': 'blacklist_pattern',  # Blacklisted IPs
            r'syn.*?scan': 'syn_scan_pattern',  # SYN scan detection
            r'rst.*?flood': 'rst_flood_pattern'  # RST flood detection
        }
    
    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        features = []
        for text in X:
            text_lower = text.lower()
            feature_vector = []
            
            # Count keyword matches for each severity level
            critical_count = sum(1 for kw in self.critical_keywords if kw in text_lower)
            high_count = sum(1 for kw in self.high_keywords if kw in text_lower)
            medium_count = sum(1 for kw in self.medium_keywords if kw in text_lower)
            low_count = sum(1 for kw in self.low_keywords if kw in text_lower)
            
            # Normalize by text length
            text_len = max(len(text.split()), 1)
            feature_vector.extend([
                critical_count / text_len,
                high_count / text_len,
                medium_count / text_len,
                low_count / text_len
            ])
            
            # Network pattern features
            for pattern, name in self.network_patterns.items():
                matches = len(re.findall(pattern, text_lower))
                feature_vector.append(matches)
            
            # Additional semantic features
            feature_vector.extend([
                1 if 'detected' in text_lower else 0,
                1 if 'blocked' in text_lower else 0,
                1 if 'failed' in text_lower else 0,
                1 if 'successful' in text_lower else 0,
                1 if any(word in text_lower for word in ['multiple', 'many', 'numerous']) else 0,
                len(re.findall(r'\d+', text)),  # Number count
                len([w for w in text.split() if w.isupper()]) / text_len,  # Uppercase ratio
            ])
            
            features.append(feature_vector)
        
        return np.array(features)

# 📌 Enhanced Training Data with 60+ Examples Per Class
def create_enhanced_dataset():
    """Create a larger, more diverse dataset with clearer severity patterns"""
    
    data = []
    
    # Critical - Active breaches, compromises, data theft (60 examples)
    critical_samples = [
        "Ransomware encryption detected on file server - 1000 files encrypted",
        "Active data exfiltration detected - customer database being downloaded",
        "Domain controller compromised - attacker has full network access",
        "Zero-day exploit successful - remote code execution on web server", 
        "APT group persistence detected - backdoor installed on critical systems",
        "Root access gained on production database server",
        "Command and control communication detected from 15 endpoints",
        "Cryptocurrency mining malware detected on 50 workstations",
        "Admin credentials compromised - unauthorized privilege escalation",
        "Nation-state actor detected - advanced persistent threat confirmed",
        "Buffer overflow exploit successful - system shell access gained",
        "SQL injection successful - database contents being extracted",
        "Insider threat detected - privileged user stealing sensitive data",
        "Rootkit installation detected on critical infrastructure",
        "Living off the land attack - PowerShell Empire framework detected",
        "Fileless malware detected - memory-only execution",
        "Keylogger detected capturing financial system passwords",
        "Lateral movement detected - attacker accessing multiple servers",
        "Bootkit detected - persistent malware in system firmware",
        "Supply chain attack detected - compromised software update",
        "Credential harvesting detected - password stealer active",
        "Remote access trojan detected with C2 communication",
        "Database breach confirmed - 10 million records compromised",
        "System administrator account completely compromised",
        "Critical vulnerability being actively exploited in production",
        "Data destruction malware detected - wiping system files",
        "Network reconnaissance complete - attacker mapping infrastructure",
        "Privilege escalation successful - local admin to domain admin",
        "Advanced malware detected with anti-analysis capabilities",
        "Persistent backdoor established in network infrastructure",
        "Financial system breach - unauthorized transactions detected",
        "Healthcare data breach - patient records being accessed",
        "Government system compromise - classified data at risk",
        "Industrial control system breach - SCADA network compromised",
        "Cryptocurrency exchange hack - user funds being stolen",
        "Source code theft detected - intellectual property compromised",
        "Email server breach - all corporate communications compromised",
        "VPN infrastructure compromised - remote access fully controlled",
        "Authentication bypass successful - all security controls defeated",
        "Memory injection attack successful - process hollowing detected",
        "DNS hijacking attack successful - traffic being redirected",
        "Man-in-the-middle attack active - encrypted traffic being intercepted",
        "Time bomb malware detected - scheduled for mass destruction",
        "Steganography detected - data hidden in image files for exfiltration",
        "Watering hole attack successful - legitimate website compromised",
        "Social engineering successful - CEO credentials compromised",
        "Physical security breach - unauthorized access to data center",
        "Mobile device management breach - all company phones compromised",
        "Cloud infrastructure breach - entire AWS environment compromised",
        "Backup system breach - all recovery options compromised",
        "Network segmentation bypassed - attacker in secure zone",
        "Certificate authority compromised - all SSL/TLS traffic at risk",
        "Hardware implant detected - compromised network equipment",
        "Firmware compromise detected - UEFI rootkit installation",
        "Air-gapped network breach - isolated systems compromised",
        "Quantum encryption broken - future-proof security defeated",
        "AI model poisoning detected - machine learning systems compromised",
        "Blockchain attack successful - cryptocurrency network compromised",
        "5G infrastructure breach - cellular network completely compromised",
        "Satellite communication breach - space-based assets compromised"
        "Cryptocurrency mining malware detected on critical infrastructure",
        "Privilege escalation attack successful - local admin to domain admin",
        "Active insider threat - privileged user downloading classified data",
        "Buffer overflow exploit successful - system shell access gained",
        "Nation-state actor tools detected on network",
        "Supply chain compromise - malicious code in vendor software",
        "Critical vulnerability being actively exploited across network",
        "Data breach confirmed - 100000 customer records accessed",
        "Lateral movement detected - attacker spreading across network segments",
        "Persistent backdoor established in firmware",
        "Authentication bypass exploit successful on financial system",
        "Active directory database compromised",
        "Real-time credential harvesting detected on login servers",
        "Traffic involving blacklisted IP detected: 203.0.113.4 -> 10.0.0.3 | port 445 | flags S",
        "Possible SYN port scan detected from 10.0.0.8 (SYNs=500 in 60s)",
        "High number of RST packets from 172.16.0.12 (1000 in 60s) - possible DDoS attack"
    ]
    
    # High - Serious security incidents requiring immediate attention (60 examples)
    high_samples = [
        "Malware detected and quarantined on 5 user workstations",
        "Brute force attack detected - 1000 login attempts in 10 minutes",
        "SQL injection attempt detected on customer portal",
        "Phishing email clicked by 25 employees - credentials potentially compromised", 
        "Suspicious PowerShell execution detected on server",
        "Unauthorized file encryption detected on shared drive",
        "Cross-site scripting attack blocked on web application",
        "Credential stuffing attack detected on login portal",
        "Password spraying attack targeting admin accounts",
        "Suspicious DNS queries to known malicious domains",
        "Lateral movement attempt detected between network segments",
        "Privilege escalation attempt blocked by security controls",
        "Endpoint protection detected trojan horse installation",
        "Web application firewall blocked directory traversal attack",
        "Suspicious file download from known malware hosting site",
        "Anomalous network traffic patterns detected",
        "Failed authentication attempts from 50 different IP addresses",
        "Suspicious registry modifications detected on workstation",
        "Unauthorized software installation attempt on production server",
        "Data loss prevention system blocked sensitive file transfer",
        "Suspicious API calls detected from compromised application",
        "Unusual process spawning behavior detected on endpoint",
        "Security agent disabled temporarily by unknown user",
        "Vulnerability scanner detected on internal network",
        "Suspicious email attachment executed by user",
        "Unusual outbound data transfer detected after hours",
        "Multiple account lockouts from same subnet detected",
        "Unauthorized modification to system scheduled tasks",
        "Suspicious script execution detected in user profile",
        "Antivirus bypass attempt detected on endpoint",
        "Password policy violation - weak credentials detected",
        "Suspicious USB device activity detected",
        "Unauthorized network share access attempt",
        "Failed VPN authentication from unusual location",
        "Suspicious web browsing to potential command and control sites",
        "Email security gateway blocked malicious attachment",
        "Network intrusion detection system triggered multiple alerts",
        "Suspicious file hash detected in system memory",
        "Unauthorized printer access from external device",
        "Mobile device policy violation detected",
        "Suspicious database query activity detected",
        "Failed SSH authentication attempts from external IPs",
        "Suspicious certificate installation detected",
        "Unauthorized remote desktop connection attempt",
        "Suspicious network port scanning detected internally",
        "Failed privilege escalation attempt logged",
        "Suspicious process injection detected",
        "Unauthorized file system access attempt",
        "Suspicious network protocol usage detected",
        "Failed application authentication from multiple sources",
        "Possible SYN port scan detected from 10.0.0.5 (SYNs=100 in 60s)",
        "Possible horizontal port scan from 192.168.1.100 hitting 50 unique ports in 60s",
        "High number of RST packets from 172.16.0.12 (200 in 60s) - possible scan",
        "Traffic involving blacklisted IP detected: 5.6.7.8 -> 10.0.0.5 | port 80 | flags S",
        "Detected connection attempts to multiple high-risk ports from 192.0.2.55",
        "Suspicious outbound traffic to known bad IP addresses",
        "Network anomaly detected - unusual protocol usage",
        "Failed network authentication from suspicious source",
        "Unauthorized network service discovery attempt",
        "Suspicious network traffic encryption patterns detected"
        "Credential stuffing attack detected against user accounts",
        "Suspicious DNS queries to known malicious domains",
        "Endpoint protection detected advanced threat behavior",
        "VPN access from high-risk country for executive account",
        "Multiple security tools disabled on endpoint",
        "Suspicious registry modifications detected indicating malware",
        "Unusual outbound data transfer detected after hours - 10GB",
        "Password spraying attack detected across multiple accounts",
        "Suspicious API calls detected from compromised application",
        "Network scanner activity detected from internal subnet",
        "Antivirus bypass technique detected in email attachment",
        "Privilege escalation attempt detected on web server",
        "Data loss prevention system blocked sensitive file transfer",
        "Possible horizontal port scan from 192.168.1.100 hitting 50 unique ports in 60s",
        "Possible SYN port scan detected from 10.0.0.5 (SYNs=100 in 60s)",
        "High number of RST packets from 172.16.0.15 (200 in 60s) - scanning activity"
    ]
    
    # Medium - Concerning activities requiring investigation
    medium_samples = [
        "Multiple failed login attempts detected on user account (15 attempts)",
        "New device logged in from unusual geographic location",
        "User account granted administrative privileges outside change window",
        "Unusual file access pattern detected - accessing 100 files rapidly",
        "Expired SSL certificate detected in production environment",
        "USB device policy violation - unauthorized device connected",
        "Email attachment with suspicious file extension detected",
        "Failed VPN authentication attempts from single IP address",
        "Suspicious web browsing activity to newly registered domains",
        "Database query anomaly detected - unusual table access pattern",
        "Mobile device compliance policy violation detected",
        "User downloading files outside normal business hours",
        "Service account used from non-server location",
        "Multiple password reset requests in short timeframe",
        "Geolocation inconsistency detected for user login",
        "Shared account accessed from multiple locations simultaneously",
        "File share access from unmanaged device",
        "Unusual application behavior detected on workstation",
        "Non-standard network protocol usage detected",
        "Security software update failed on multiple endpoints",
        "Possible SYN port scan detected from 10.0.0.2 (SYNs=25 in 60s)",
        "Multiple connection attempts to different ports from internal host",
        "Unusual network traffic pattern detected from user workstation",
        "Account lockout threshold reached for service account",
        "Unusual login time detected for regular business user",
        "File modification detected on shared network drive",
        "Password complexity policy violation detected",
        "Unauthorized software installation attempt detected",
        "User accessing resources outside normal pattern",
        "Email forwarding rule created to external domain",
        "Suspicious file upload to cloud storage service",
        "Failed authentication to corporate application",
        "Unusual bandwidth usage detected from user account",
        "Non-encrypted connection attempt to secure system",
        "Developer credentials used from non-development machine",
        "Multiple user accounts created in short timeframe",
        "Suspicious printer usage detected outside business hours",
        "File deletion activity detected in sensitive directory",
        "User account disabled due to inactivity reactivated",
        "Unusual database connection patterns detected",
        "Failed wireless network authentication attempts",
        "Suspicious email sending patterns detected",
        "User downloading large files from internet",
        "Application error logs showing potential security issues",
        "Network drive mapping from unusual location",
        "Service restart outside scheduled maintenance window",
        "User account privilege change detected",
        "Unusual remote access patterns detected",
        "Failed backup authentication detected",
        "Suspicious calendar meeting creation patterns",
        "User accessing multiple systems rapidly",
        "File compression activity detected on sensitive data",
        "Unusual virtual machine creation activity",
        "Failed login attempts from multiple service accounts",
        "Suspicious file access timing patterns detected",
        "User downloading unusual file types from internet",
        "Non-standard application usage detected"
    ]
    
    # Low - Normal operations, routine activities (60 examples)
    low_samples = [
        "Scheduled security scan completed successfully - no threats found",
        "System backup operation completed successfully",
        "Routine password change completed for service account", 
        "Software update deployed successfully to 100 endpoints",
        "Employee completed mandatory security training course",
        "Standard system maintenance window completed",
        "Antivirus signature update deployed successfully",
        "User logged in successfully during business hours",
        "Authorized file transfer completed via secure channel",
        "Regular VPN connection established from known location",
        "System health check completed - all services running",
        "Database maintenance operation completed successfully",
        "Normal user authentication to corporate applications",
        "Scheduled vulnerability scan initiated",
        "Standard network connectivity test passed",
        "Regular log rotation operation completed",
        "Authorized software installation completed",
        "Normal system startup sequence completed",
        "User account provisioning completed per HR request",
        "Regular compliance check passed - no violations",
        "System monitoring alert cleared - false positive",
        "Network interface auto-detection completed successfully",
        "IDS system startup completed - monitoring active",
        "Automated patch deployment completed successfully",
        "Regular certificate renewal completed",
        "Standard firewall rule update applied",
        "Normal business hours login activity",
        "Scheduled database optimization completed",
        "Regular system performance monitoring",
        "Standard user group membership update",
        "Normal application startup sequence",
        "Routine security policy compliance check",
        "Standard network device health check",
        "Regular backup verification completed",
        "Normal email flow processing",
        "Standard DNS resolution activity",
        "Regular system clock synchronization",
        "Normal file system permissions check",
        "Standard load balancer health check",
        "Regular SSL certificate validation",
        "Normal web server access logs",
        "Standard database connection pooling",
        "Regular system resource monitoring",
        "Normal network traffic baseline",
        "Standard application performance metrics",
        "Regular disk space monitoring",
        "Normal user session management",
        "Standard API endpoint health check",
        "Regular security baseline validation",
        "Normal business application usage",
        "Standard system service status check",
        "Regular network latency monitoring",
        "Normal data synchronization process",
        "Standard cache refresh operation",
        "Regular log aggregation process",
        "Normal authentication token refresh",
        "Standard configuration validation",
        "Regular system update check",
        "Normal user profile synchronization",
        "Standard service discovery operation"
    ]
    
    # Compile all data with labels
    for sample in critical_samples:
        data.append((sample, "Critical"))
    for sample in high_samples:
        data.append((sample, "High"))
    for sample in medium_samples:
        data.append((sample, "Medium"))
    for sample in low_samples:
        data.append((sample, "Low"))
    
    return data

# 📌 Main Training Pipeline
def train_enhanced_model():
    print("🚀 Starting Enhanced Security Alert Classification Training")
    
    # Create comprehensive dataset
    data = create_enhanced_dataset()
    df = pd.DataFrame(data, columns=["message", "severity"])
    
    print(f"📊 Dataset Statistics:")
    print(f"Total examples: {len(df)}")
    print(f"Class distribution:")
    print(df["severity"].value_counts())
    
    # Encode labels
    severity_mapping = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    df["severity_num"] = df["severity"].map(severity_mapping)
    
    # Stratified split to ensure balanced representation
    X_train, X_test, y_train, y_test = train_test_split(
        df["message"], df["severity_num"],
        test_size=0.2,
        stratify=df["severity_num"],
        random_state=42
    )
    
    print(f"\n📈 Data Split:")
    print(f"Training: {len(X_train)} examples")
    print(f"Testing: {len(X_test)} examples")
    
    # 📌 Feature Engineering Pipeline
    # Combine TF-IDF with custom security features
    tfidf = TfidfVectorizer(
        max_features=2000,
        ngram_range=(1, 3),  # Include trigrams for better context
        stop_words='english',
        min_df=1,
        max_df=0.9,
        sublinear_tf=True  # Use log scaling for better performance
    )
    
    security_features = SecurityKeywordExtractor()
    
    # Create feature union
    from sklearn.pipeline import FeatureUnion
    features = FeatureUnion([
        ('tfidf', tfidf),
        ('security_keywords', security_features)
    ])
    
    # 📌 Ensemble Model with Multiple Algorithms
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        min_samples_split=3,
        min_samples_leaf=1,
        class_weight='balanced',
        random_state=42
    )
    
    svm = SVC(
        kernel='rbf',
        C=10,
        gamma='scale',
        class_weight='balanced',
        probability=True,
        random_state=42
    )
    
    gb = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        random_state=42
    )
    
    lr = LogisticRegression(
        C=1.0,
        class_weight='balanced',
        max_iter=1000,
        random_state=42
    )
    
    # Create voting ensemble
    ensemble = VotingClassifier([
        ('rf', rf),
        ('svm', svm),
        ('gb', gb),
        ('lr', lr)
    ], voting='soft')
    
    # Complete pipeline
    pipeline = Pipeline([
        ('features', features),
        ('classifier', ensemble)
    ])
    
    print(f"\n🔄 Training ensemble model...")
    pipeline.fit(X_train, y_train)
    
    # 📌 Comprehensive Evaluation
    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n🎯 Model Performance:")
    print(f"Test Accuracy: {accuracy:.3f}")
    
    target_names = ["Low", "Medium", "High", "Critical"]
    print(f"\n📋 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))
    
    # Cross-validation for robust evaluation
    cv_scores = cross_val_score(pipeline, X_train, y_train, 
                               cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
                               scoring='accuracy')
    print(f"\n🔄 Cross-Validation Results:")
    print(f"CV Accuracy: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"\n🔍 Confusion Matrix:")
    print("       Predicted:")
    print("       Low  Med High Crit")
    for i, actual in enumerate(target_names):
        print(f"Act {actual:>4}: {cm[i]}")
    
    # Test predictions on sample messages
    print(f"\n🧪 Sample Predictions:")
    test_messages = [
        "Ransomware detected encrypting critical business files",
        "Brute force attack detected on admin portal - 500 attempts",
        "Failed login attempt from unusual geographic location", 
        "System backup completed successfully",
        "Possible SYN port scan detected from external IP (SYNs=200 in 60s)"
    ]
    
    for msg in test_messages:
        pred_num = pipeline.predict([msg])[0]
        pred_label = target_names[pred_num]
        confidence = max(pipeline.predict_proba([msg])[0])
        print(f"'{msg[:60]}...' → {pred_label} ({confidence:.2f})")
    
    # Save the enhanced model
    print(f"\n💾 Saving enhanced model...")
    
    # For compatibility with existing app.py, also save individual components
    tfidf_only = TfidfVectorizer(
        max_features=2000,
        ngram_range=(1, 2),
        stop_words='english',
        min_df=1,
        max_df=0.9
    )
    
    X_train_tfidf = tfidf_only.fit_transform(X_train)
    simple_rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        class_weight='balanced',
        random_state=42
    )
    simple_rf.fit(X_train_tfidf, y_train)
    
    joblib.dump(pipeline, "enhanced_alert_classifier.pkl")
    joblib.dump(simple_rf, "alert_classifier.pkl")  # For backward compatibility
    joblib.dump(tfidf_only, "tfidf_vectorizer.pkl")
    
    print(f"✅ Training Complete!")
    print(f"📁 Saved: enhanced_alert_classifier.pkl (main model)")
    print(f"📁 Saved: alert_classifier.pkl (compatibility model)")  
    print(f"📁 Saved: tfidf_vectorizer.pkl (vectorizer)")
    print(f"🎯 Final Accuracy: {accuracy:.1%}")
    
    return pipeline, accuracy

if __name__ == "__main__":
    model, accuracy = train_enhanced_model()
