import pandas as pd
import numpy as np
import json
import re
import os
import xml.etree.ElementTree as ET
import smtplib
import hashlib
import pickle
import datetime
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.linear_model import LinearRegression
from sklearn.ensemble import RandomForestRegressor
import matplotlib.pyplot as plt
from collections import Counter


class LogClassifier:
    def _init_(self, model_name="distilbert-base-uncased"):
        """Initialize the log classifier with a pretrained model."""
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name)

        # Zero-shot classification pipeline for flexible log categorization
        self.classifier = pipeline(
            "zero-shot-classification",
            model="facebook/bart-large-mnli"
        )

        # Sentiment analysis for error severity assessment
        self.sentiment_analyzer = pipeline(
            "sentiment-analysis",
            model="distilbert-base-uncased-finetuned-sst-2-english"
        )

        # For clustering similar logs
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.cluster_model = KMeans(n_clusters=5)

        # Define common error and log patterns
        self.error_patterns = [
            r'error', r'exception', r'fail', r'critical', r'severe',
            r'warning', r'timeout', r'unavailable', r'could not', r'denied'
        ]

        # Possible log categories for zero-shot classification
        self.log_categories = [
            "authentication failure", "network error", "database error",
            "memory issue", "timeout", "configuration error", "successful operation",
            "system startup", "system shutdown", "user activity"
        ]

        # Alert configuration
        self.alert_config = {
            "enabled": False,
            "email": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "from_email": "",
                "recipients": []
            },
            "slack": {
                "enabled": False,
                "webhook_url": ""
            },
            "sms": {
                "enabled": False,
                "api_key": "",
                "from_number": "",
                "to_numbers": []
            },
            "thresholds": {
                "error_percentage": 20,  # Alert if error percentage exceeds this value
                "high_severity_count": 5,  # Alert if high severity errors exceed this count
                "critical_categories": {  # Category-specific thresholds
                    "authentication failure": 3,
                    "database error": 3,
                    "network error": 5
                }
            }
        }

        # Historical data for predictive analysis
        self.historical_data_file = "log_history.pkl"
        self.historical_data = self._load_historical_data()

        # User roles and permissions
        self.users = {}
        self.roles = {
            "admin": {
                "permissions": ["view_all", "search", "configure", "alerts", "predictions", "remedies"]
            },
            "developer": {
                "permissions": ["view_project", "search", "remedies"]
            },
            "manager": {
                "permissions": ["view_project", "alerts", "predictions"]
            },
            "viewer": {
                "permissions": ["view_project"]
            }
        }
        self._load_users()

    def _load_historical_data(self):
        """Load historical log analysis data if available."""
        if os.path.exists(self.historical_data_file):
            try:
                with open(self.historical_data_file, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"Error loading historical data: {e}")
                return []
        return []

    def _save_historical_data(self):
        """Save historical data for future predictions."""
        try:
            with open(self.historical_data_file, 'wb') as f:
                pickle.dump(self.historical_data, f)
        except Exception as e:
            print(f"Error saving historical data: {e}")

    def _load_users(self):
        """Load user accounts and roles."""
        if os.path.exists("users.json"):
            try:
                with open("users.json", 'r') as f:
                    self.users = json.load(f)
            except Exception as e:
                print(f"Error loading user data: {e}")

    def _save_users(self):
        """Save user accounts and roles."""
        try:
            with open("users.json", 'w') as f:
                json.dump(self.users, f)
        except Exception as e:
            print(f"Error saving user data: {e}")

    def add_user(self, username, password, role, projects=None):
        """Add a new user with specified role and project access."""
        if role not in self.roles:
            raise ValueError(f"Invalid role: {role}. Available roles: {list(self.roles.keys())}")

        # Hash password for security
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        self.users[username] = {
            "password_hash": password_hash,
            "role": role,
            "projects": projects if projects else []
        }

        self._save_users()
        return True

    def authenticate_user(self, username, password):
        """Authenticate a user and return their role and permissions."""
        if username not in self.users:
            return None

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != self.users[username]["password_hash"]:
            return None

        user_data = self.users[username]
        permissions = self.roles[user_data["role"]]["permissions"]

        return {
            "username": username,
            "role": user_data["role"],
            "permissions": permissions,
            "projects": user_data["projects"]
        }

    def has_permission(self, user_auth, permission, project=None):
        """Check if a user has a specific permission, potentially for a specific project."""
        if not user_auth:
            return False

        if "view_all" in user_auth["permissions"]:
            return True

        if permission in user_auth["permissions"]:
            if permission == "view_project" and project:
                return project in user_auth["projects"] or "all" in user_auth["projects"]
            return True

        return False

    def load_file(self, file_path):
        """Load log data from various file formats."""
        file_extension = os.path.splitext(file_path)[1].lower()

        if file_extension == '.csv':
            return self._load_csv(file_path)
        elif file_extension == '.json':
            return self._load_json(file_path)
        elif file_extension == '.xml':
            return self._load_xml(file_path)
        elif file_extension in ['.txt', '.log']:
            return self._load_text(file_path)
        else:
            raise ValueError(f"Unsupported file extension: {file_extension}")

    def _load_csv(self, file_path):
        """Load and extract log entries from CSV file."""
        df = pd.read_csv(file_path)
        # Try to identify message column
        message_cols = [col for col in df.columns if
                        any(x in col.lower() for x in ['message', 'log', 'text', 'description'])]
        if message_cols:
            return df[message_cols[0]].astype(str).tolist()
        # If no message column found, concatenate all columns
        return df.astype(str).apply(lambda x: ' '.join(x), axis=1).tolist()

    def _load_json(self, file_path):
        """Extract log messages from JSON file."""
        with open(file_path, 'r') as f:
            data = json.load(f)

        logs = []
        # Handle both array and object formats
        if isinstance(data, list):
            for entry in data:
                logs.append(self._extract_message_from_dict(entry))
        else:
            logs.append(self._extract_message_from_dict(data))
        return logs

    def _extract_message_from_dict(self, entry_dict):
        """Extract message field from a dictionary, handles nested structures."""
        if isinstance(entry_dict, dict):
            # Look for common log message fields
            for key in ['message', 'msg', 'log', 'text', 'description']:
                if key in entry_dict:
                    return str(entry_dict[key])

            # If no direct match, combine all values
            return " ".join(str(v) for v in entry_dict.values())
        return str(entry_dict)

    def _load_xml(self, file_path):
        """Extract log messages from XML file."""
        tree = ET.parse(file_path)
        root = tree.getroot()

        logs = []
        # Look for log entries or messages
        for elem in root.findall(".//log") + root.findall(".//entry") + root.findall(".//message"):
            logs.append(elem.text)

        # If no specific log elements found, get all text
        if not logs:
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    logs.append(elem.text.strip())

        return logs

    def _load_text(self, file_path):
        """Load log entries from text or log file."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.readlines()

        # Remove empty lines and strip whitespace
        return [line.strip() for line in content if line.strip()]

    def preprocess_logs(self, logs):
        """Clean and normalize log entries."""
        processed_logs = []
        for log in logs:
            # Convert to string if not already
            log = str(log)
            # Remove timestamps (common in logs)
            log = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z', '', log)
            log = re.sub(r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]', '', log)
            # Remove IP addresses
            log = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_ADDRESS]', log)
            # Remove excess whitespace
            log = re.sub(r'\s+', ' ', log).strip()
            processed_logs.append(log)
        return processed_logs

    def classify_logs(self, logs):
        """Classify logs using zero-shot classification."""
        results = []
        for log in logs:
            # Truncate very long logs to prevent token limit issues
            truncated_log = log[:512] if len(log) > 512 else log

            # Classify the log entry
            classification = self.classifier(
                truncated_log,
                self.log_categories,
                multi_label=False
            )

            # Determine if this is an error log
            is_error = any(re.search(pattern, log.lower()) for pattern in self.error_patterns)

            # Analyze sentiment/severity
            sentiment = self.sentiment_analyzer(truncated_log)[0]

            results.append({
                'log': log,
                'category': classification['labels'][0],
                'confidence': classification['scores'][0],
                'is_error': is_error,
                'sentiment': sentiment['label'],
                'severity': 'high' if is_error and sentiment[
                    'label'] == 'NEGATIVE' else 'medium' if is_error else 'low',
                'timestamp': datetime.datetime.now().isoformat()
            })

        return results

    def cluster_logs(self, logs):
        """Group similar logs together."""
        # Create feature vectors
        X = self.vectorizer.fit_transform(logs)

        # Perform clustering
        clusters = self.cluster_model.fit_predict(X)

        return clusters

    def generate_summary(self, classified_logs):
        """Generate a summary of the log analysis."""
        total_logs = len(classified_logs)
        error_logs = sum(1 for log in classified_logs if log['is_error'])

        # Count occurrences of each category
        categories = Counter([log['category'] for log in classified_logs])

        # Count severity levels
        severity = Counter([log['severity'] for log in classified_logs])

        summary = {
            'total_logs': total_logs,
            'error_percentage': (error_logs / total_logs) * 100 if total_logs > 0 else 0,
            'categories': dict(categories),
            'severity': dict(severity),
            'top_errors': [log['log'] for log in classified_logs if log['is_error'] and log['severity'] == 'high'][:5],
            'timestamp': datetime.datetime.now().isoformat()
        }

        return summary

    def suggest_remedies(self, classified_logs):
        """Suggest remedies for common error patterns."""
        remedies = []

        # Look for authentication errors
        auth_errors = [log for log in classified_logs if
                       log['category'] == 'authentication failure' and log['is_error']]
        if auth_errors:
            remedies.append({
                'issue': 'Authentication failures detected',
                'remedy': 'Check user credentials and authentication services. Verify that authentication servers are responding correctly.',
                'count': len(auth_errors)
            })

        # Look for network errors
        network_errors = [log for log in classified_logs if log['category'] == 'network error' and log['is_error']]
        if network_errors:
            remedies.append({
                'issue': 'Network connectivity issues detected',
                'remedy': 'Verify network configurations, check firewall settings, and ensure DNS resolution is working properly.',
                'count': len(network_errors)
            })

        # Look for database errors
        db_errors = [log for log in classified_logs if log['category'] == 'database error' and log['is_error']]
        if db_errors:
            remedies.append({
                'issue': 'Database errors detected',
                'remedy': 'Check database connection parameters, ensure database service is running, and verify query syntax.',
                'count': len(db_errors)
            })

        # Look for timeout issues
        timeout_errors = [log for log in classified_logs if log['category'] == 'timeout' and log['is_error']]
        if timeout_errors:
            remedies.append({
                'issue': 'Timeout errors detected',
                'remedy': 'Consider increasing timeout thresholds, optimize slow operations, or check for resource constraints.',
                'count': len(timeout_errors)
            })

        # Look for memory issues
        memory_errors = [log for log in classified_logs if log['category'] == 'memory issue' and log['is_error']]
        if memory_errors:
            remedies.append({
                'issue': 'Memory-related issues detected',
                'remedy': 'Check for memory leaks, increase available memory, or optimize memory-intensive operations.',
                'count': len(memory_errors)
            })

        return remedies

    def visualize_results(self, summary):
        """Create visualization of log analysis results."""
        # Create two subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        # Plot category distribution
        categories = list(summary['categories'].keys())
        category_counts = list(summary['categories'].values())
        ax1.bar(categories, category_counts)
        ax1.set_title('Log Categories Distribution')
        ax1.set_xlabel('Category')
        ax1.set_ylabel('Number of Logs')
        ax1.tick_params(axis='x', rotation=45)

        # Plot severity distribution
        severity_labels = list(summary['severity'].keys())
        severity_counts = list(summary['severity'].values())
        ax2.pie(severity_counts, labels=severity_labels, autopct='%1.1f%%')
        ax2.set_title('Log Severity Distribution')

        plt.tight_layout()
        return fig

    def configure_alerts(self, config):
        """Configure the alert notification system."""
        self.alert_config.update(config)
        return True

    def send_alert(self, alert_message, severity="high", category=None):
        """Send alerts through configured channels based on severity and category."""
        if not self.alert_config["enabled"]:
            return False

        # Format alert message
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {severity.upper()} ALERT: {alert_message}"
        if category:
            formatted_message = f"[{timestamp}] {severity.upper()} ALERT ({category}): {alert_message}"

        success = False

        # Send email alerts
        if self.alert_config["email"]["enabled"]:
            try:
                msg = MIMEMultipart()
                msg['From'] = self.alert_config["email"]["from_email"]
                msg['To'] = ", ".join(self.alert_config["email"]["recipients"])
                msg['Subject'] = f"Log Analyzer Alert: {severity.upper()} - {category if category else 'System'}"

                msg.attach(MIMEText(formatted_message, 'plain'))

                server = smtplib.SMTP(
                    self.alert_config["email"]["smtp_server"],
                    self.alert_config["email"]["smtp_port"]
                )
                server.starttls()
                server.login(
                    self.alert_config["email"]["username"],
                    self.alert_config["email"]["password"]
                )
                server.send_message(msg)
                server.quit()
                success = True
                print(f"Email alert sent: {formatted_message}")
            except Exception as e:
                print(f"Failed to send email alert: {e}")

        # Send Slack alerts
        if self.alert_config["slack"]["enabled"]:
            try:
                payload = {
                    "text": formatted_message
                }
                response = requests.post(
                    self.alert_config["slack"]["webhook_url"],
                    json=payload
                )
                if response.status_code == 200:
                    success = True
                    print(f"Slack alert sent: {formatted_message}")
                else:
                    print(f"Failed to send Slack alert. Status code: {response.status_code}")
            except Exception as e:
                print(f"Failed to send Slack alert: {e}")

        # Send SMS alerts
        if self.alert_config["sms"]["enabled"]:
            try:
                # This is a placeholder - you would implement your SMS gateway integration here
                # For example, using Twilio, AWS SNS, or another SMS service
                print(
                    f"SMS alert would be sent to {len(self.alert_config['sms']['to_numbers'])} recipients: {formatted_message}")
                success = True
            except Exception as e:
                print(f"Failed to send SMS alert: {e}")

        return success

    def check_alert_thresholds(self, summary):
        """Check if current log analysis results exceed alert thresholds."""
        if not self.alert_config["enabled"]:
            return []

        alerts = []

        # Check overall error percentage
        if summary["error_percentage"] > self.alert_config["thresholds"]["error_percentage"]:
            alert_msg = f"Error percentage ({summary['error_percentage']:.2f}%) exceeds threshold ({self.alert_config['thresholds']['error_percentage']}%)"
            alerts.append({"message": alert_msg, "severity": "high"})

        # Check high severity count
        high_severity_count = summary["severity"].get("high", 0)
        if high_severity_count > self.alert_config["thresholds"]["high_severity_count"]:
            alert_msg = f"High severity errors ({high_severity_count}) exceed threshold ({self.alert_config['thresholds']['high_severity_count']})"
            alerts.append({"message": alert_msg, "severity": "high"})

        # Check category-specific thresholds
        for category, threshold in self.alert_config["thresholds"]["critical_categories"].items():
            if category in summary["categories"] and summary["categories"][category] > threshold:
                alert_msg = f"{category} issues ({summary['categories'][category]}) exceed threshold ({threshold})"
                alerts.append({"message": alert_msg, "severity": "medium", "category": category})

        return alerts

    def search_logs(self, classified_logs, query=None, filters=None, regex=None):
        """Search through classified logs with keywords, filters, or regex patterns."""
        results = classified_logs.copy()

        # Apply text search if provided
        if query:
            query = query.lower()
            results = [log for log in results if query in log["log"].lower()]

        # Apply filters if provided
        if filters:
            for key, value in filters.items():
                if key in ["category", "severity"]:
                    results = [log for log in results if log.get(key) == value]
                elif key == "is_error":
                    results = [log for log in results if log.get("is_error") == value]
                elif key == "confidence":
                    # Filter by minimum confidence threshold
                    results = [log for log in results if log.get("confidence", 0) >= value]

        # Apply regex pattern if provided
        if regex:
            try:
                pattern = re.compile(regex, re.IGNORECASE)
                results = [log for log in results if pattern.search(log["log"])]
            except re.error:
                print(f"Invalid regex pattern: {regex}")

        return results

    def analyze_trends(self, project=None):
        """Analyze historical trends for a specific project or all projects."""
        if not self.historical_data:
            return {"message": "Not enough historical data for trend analysis"}

        # Filter by project if specified
        project_data = self.historical_data
        if project:
            project_data = [entry for entry in self.historical_data if entry.get("project") == project]

        if len(project_data) < 5:  # Need some minimum data points
            return {"message": "Not enough historical data for this project"}

        # Prepare data for regression
        timestamps = []
        error_percentages = []
        high_severity_counts = []

        for entry in project_data:
            # Convert timestamp to a numeric value (days since epoch)
            try:
                dt = datetime.datetime.fromisoformat(entry["summary"]["timestamp"])
                days_since_epoch = (dt - datetime.datetime(1970, 1, 1)).days
                timestamps.append(days_since_epoch)

                # Get error percentage and high severity count
                error_percentages.append(entry["summary"]["error_percentage"])
                high_severity_counts.append(entry["summary"]["severity"].get("high", 0))
            except (ValueError, KeyError):
                continue

        if len(timestamps) < 3:
            return {"message": "Not enough valid historical data points"}

        # Convert to numpy arrays for regression
        X = np.array(timestamps).reshape(-1, 1)
        y_error = np.array(error_percentages)
        y_high = np.array(high_severity_counts)

        # Fit linear regression models
        error_model = LinearRegression().fit(X, y_error)
        high_model = LinearRegression().fit(X, y_high)

        # Predict next 7 days
        today = datetime.datetime.now()
        future_days = [(today + datetime.timedelta(days=i) - datetime.datetime(1970, 1, 1)).days for i in range(1, 8)]
        X_future = np.array(future_days).reshape(-1, 1)

        error_predictions = error_model.predict(X_future)
        high_predictions = high_model.predict(X_future)

        # Create predictions dictionary
        predictions = {
            "dates": [(today + datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(1, 8)],
            "error_percentage": error_predictions.tolist(),
            "high_severity_count": high_predictions.tolist(),
            "trend": "increasing" if error_model.coef_[0] > 0 else "decreasing",
            "coefficient": float(error_model.coef_[0])
        }

        # Generate preventive recommendations based on trends
        recommendations = []
        if error_model.coef_[0] > 0.5:  # Strong upward trend in errors
            recommendations.append("Error rates are rising rapidly. Consider a code freeze and comprehensive review.")
        elif error_model.coef_[0] > 0.1:  # Moderate upward trend
            recommendations.append(
                "Error rates are gradually increasing. Schedule additional testing and review cycles.")

        if high_model.coef_[0] > 0.2:  # Increasing high severity errors
            recommendations.append(
                "High severity errors are trending upward. Review critical components and error handling.")

        # Add category-specific recommendations
        if "category_trends" in project_data[-1]:
            for category, count in project_data[-1]["category_trends"].items():
                prev_count = next((entry.get("category_trends", {}).get(category, 0) for entry in project_data[-2:-1]),
                                  0)
                if count > prev_count and category in ["database error", "network error", "authentication failure"]:
                    recommendations.append(
                        f"Rising trend in {category} errors. Schedule focused testing of {category.split()[0]} components.")

        predictions["recommendations"] = recommendations

        return predictions

    def process_logs(self, file_path, project=None, user_auth=None):
        """Complete log processing pipeline with access control."""
        # Check permissions if user authentication is provided
        if user_auth and not self.has_permission(user_auth, "view_project", project):
            return {"error": "Access denied. User does not have permission to view this project."}

        # Load logs from file
        logs = self.load_file(file_path)
        print(f"Loaded {len(logs)} log entries")

        # Preprocess logs
        processed_logs = self.preprocess_logs(logs)

        # Classify logs
        classified_logs = self.classify_logs(processed_logs)

        # Generate summary
        summary = self.generate_summary(classified_logs)

        # Suggest remedies if user has permission
        remedies = []
        if not user_auth or self.has_permission(user_auth, "remedies"):
            remedies = self.suggest_remedies(classified_logs)

        # Cluster similar logs
        clusters = self.cluster_logs([log['log'] for log in classified_logs])

        # Add cluster information to classified logs
        for i, log_info in enumerate(classified_logs):
            log_info['cluster'] = int(clusters[i])

        # Store results in historical data for future predictions
        historical_entry = {
            "project": project,
            "summary": summary,
            "timestamp": datetime.datetime.now().isoformat(),
            "category_trends": summary["categories"]
        }
        self.historical_data.append(historical_entry)
        self._save_historical_data()

        # Check if any alerts should be triggered
        alerts = []
        if not user_auth or self.has_permission(user_auth, "alerts"):
            alerts = self.check_alert_thresholds(summary)
            for alert in alerts:
                self.send_alert(
                    alert["message"],
                    alert.get("severity", "medium"),
                    alert.get("category")
                )

        # Generate predictive insights if user has permission
        predictions = None
        if not user_auth or self.has_permission(user_auth, "predictions"):
            predictions = self.analyze_trends(project)

        result = {
            'classified_logs': classified_logs,
            'summary': summary,
            'remedies': remedies,
            'alerts': alerts
        }

        if predictions:
            result['predictions'] = predictions

        return result


# Example usage
if name == "main":
    classifier = LogClassifier()

    # Configure alerts (example)
    alert_config = {
        "enabled": True,
        "email": {
            "enabled": True,
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "username": "alerts@example.com",
            "password": "your_password",
            "from_email": "alerts@example.com",
            "recipients": ["admin@example.com", "devops@example.com"]
        },
        "slack": {
            "enabled": True,
            "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        },
        "thresholds": {
            "error_percentage": 15,  # Alert if error percentage exceeds this value
            "high_severity_count": 3  # Alert if high severity errors exceed this count
        }
    }
    classifier.configure_alerts(alert_config)

    # Add some users with different roles
    classifier.add_user("admin", "admin_pass", "admin", ["all"])
    classifier.add_user("developer1", "dev_pass", "developer", ["app1", "app2"])
    classifier.add_user("manager1", "mgr_pass", "manager", ["app1", "app2", "app3"])

    # Authenticate a user
    user = classifier.authenticate_user("developer1", "dev_pass")

    # Process logs with user authentication for access control
    results = classifier.process_logs("your_log_file.log", project="app1", user_auth=user)

    # Search logs example
    if "classified_logs" in results:
        # Search by keyword
        keyword_results = classifier.search_logs(results["classified_logs"], query="connection")
        print(f"Found {len(keyword_results)} logs containing 'connection'")

        # Search by filter
        filter_results = classifier.search_logs(
            results["classified_logs"],
            filters={"category": "database error", "severity": "high"}
        )
        print(f"Found {len(filter_results)} high severity database errors")

        # Search by regex
        regex_results = classifier.search_logs(
            results["classified_logs"],
            regex=r"failed with code \d{3}"
        )
        print(f"Found {len(regex_results)} logs matching the regex pattern")

    # Print summary
    if "summary" in results:
        print("\nLOG ANALYSIS SUMMARY:")
        print(f"Total logs analyzed: {results['summary']['total_logs']}")
        print(f"Error percentage: {results['summary']['error_percentage']:.2f}%")

        print("\nCATEGORY DISTRIBUTION:")
        for category, count in results['summary']['categories'].items():
            print(f"- {category}: {count}")

        print("\nSEVERITY DISTRIBUTION:")
        for severity, count in results['summary']['severity'].items():
            print(f"- {severity}: {count}")

        print("\nTOP ERRORS:")
        for i, error in enumerate(results['summary']['top_errors'], 1):
            print(f"{i}. {error[:100]}..." if len(error) > 100 else f"{i}. {error}")

    if "remedies" in results:
        print("\nSUGGESTED REMEDIES:")
        for remedy in results['remedies']:
            print(f"ISSUE ({remedy['count']} occurrences): {remedy['issue']}")
            print(f"REMEDY: {remedy['remedy']}\n")

    if "alerts" in results and results["alerts"]:
        print("\nALERTS TRIGGERED:")
        for alert in results["alerts"]:
            print(f"- {alert['severity'].upper()}: {alert['message']}")

    if "predictions" in results and "recommendations" in results["predictions"]:
        print("\nPREDICTIVE INSIGHTS:")
        print(f"Error trend: {results['predictions']['trend']}")
        print("\nRECOMMENDATIONS:")
        for rec in results["predictions"]["recommendations"]:
            print(f"- {rec}")

    # Create and save visualization
    fig = classifier.visualize_results(results['summary'])
    plt.savefig("log_analysis_results.png")
    print("Visualization saved as 'log_analysis_results.png'")