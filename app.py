import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import json
import os
import datetime
import pickle
import hashlib
import re
import base64
from io import BytesIO

# Import your LogClassifier
# Note: In production, you would import from your module
# from log_classifier import LogClassifier

# For this example, we'll assume LogClassifier is defined in the same file
# If LogClassifier is imported from another file, remove this placeholder class
class LogClassifier:
    # This is just a placeholder - your actual LogClassifier implementation will be used
    def authenticate_user(self, username, password):
        # In production, this calls your actual authentication method
        return self._mock_authenticate(username, password)
    
    def _mock_authenticate(self, username, password):
        # Mock authentication for testing - remove this in production
        users = {
            "admin": {"password": "admin_pass", "role": "admin", "permissions": ["view_all", "search", "configure", "alerts", "predictions", "remedies"], "projects": ["all"]},
            "developer": {"password": "dev_pass", "role": "developer", "permissions": ["view_project", "search", "remedies"], "projects": ["app1", "app2"]},
            "manager": {"password": "mgr_pass", "role": "manager", "permissions": ["view_project", "alerts", "predictions"], "projects": ["app1", "app2", "app3"]},
            "viewer": {"password": "view_pass", "role": "viewer", "permissions": ["view_project"], "projects": ["app1"]}
        }
        
        if username in users and users[username]["password"] == password:
            return {
                "username": username,
                "role": users[username]["role"],
                "permissions": users[username]["permissions"],
                "projects": users[username]["projects"]
            }
        return None
    
    def has_permission(self, user_auth, permission, project=None):
        if not user_auth:
            return False
        
        if "view_all" in user_auth["permissions"]:
            return True
            
        if permission in user_auth["permissions"]:
            if permission == "view_project" and project:
                return project in user_auth["projects"] or "all" in user_auth["projects"]
            return True
            
        return False
    
    def process_logs(self, file_path, project=None, user_auth=None):
        # In production, this calls your actual log processing method
        # This is a mock implementation for UI testing
        if user_auth and not self.has_permission(user_auth, "view_project", project):
            return {"error": "Access denied. User does not have permission to view this project."}
            
        # Mock data for testing - replace with actual processing in production
        classified_logs = [
            {
                'log': 'Connection to database failed after 3 retries',
                'category': 'database error',
                'confidence': 0.92,
                'is_error': True,
                'severity': 'high',
                'timestamp': datetime.datetime.now().isoformat(),
                'cluster': 0
            },
            {
                'log': 'User login successful for user123',
                'category': 'successful operation',
                'confidence': 0.85,
                'is_error': False,
                'severity': 'low',
                'timestamp': datetime.datetime.now().isoformat(),
                'cluster': 1
            },
            {
                'log': 'Network timeout when connecting to api.example.com',
                'category': 'network error',
                'confidence': 0.88,
                'is_error': True,
                'severity': 'medium',
                'timestamp': datetime.datetime.now().isoformat(),
                'cluster': 2
            }
        ]
        
        summary = {
            'total_logs': len(classified_logs),
            'error_percentage': 66.7,
            'categories': {'database error': 1, 'successful operation': 1, 'network error': 1},
            'severity': {'high': 1, 'medium': 1, 'low': 1},
            'top_errors': ['Connection to database failed after 3 retries', 'Network timeout when connecting to api.example.com'],
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        remedies = []
        if self.has_permission(user_auth, "remedies"):
            remedies = [
                {
                    'issue': 'Database connectivity issues detected',
                    'remedy': 'Check database connection parameters and ensure database service is running.',
                    'count': 1
                },
                {
                    'issue': 'Network connectivity issues detected',
                    'remedy': 'Verify network configurations and check firewall settings.',
                    'count': 1
                }
            ]
        
        alerts = []
        if self.has_permission(user_auth, "alerts"):
            alerts = [
                {
                    'message': 'Error percentage (66.7%) exceeds threshold (15%)',
                    'severity': 'high'
                }
            ]
        
        predictions = None
        if self.has_permission(user_auth, "predictions"):
            predictions = {
                'dates': [(datetime.datetime.now() + datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(1, 8)],
                'error_percentage': [66.7, 65.2, 63.8, 67.1, 68.5, 64.3, 62.8],
                'high_severity_count': [1, 1, 2, 2, 1, 1, 0],
                'trend': 'decreasing',
                'coefficient': -0.15,
                'recommendations': [
                    'High severity errors continue to appear. Review critical components and error handling.'
                ]
            }
        
        result = {
            'classified_logs': classified_logs,
            'summary': summary,
            'remedies': remedies,
            'alerts': alerts
        }
        
        if predictions:
            result['predictions'] = predictions
            
        return result
    
    def configure_alerts(self, config):
        # In production, this calls your actual alert configuration method
        return True
    
    def search_logs(self, classified_logs, query=None, filters=None, regex=None):
        # In production, this calls your actual search method
        results = []
        for log in classified_logs:
            if query and query.lower() not in log["log"].lower():
                continue
                
            if filters:
                skip = False
                for key, value in filters.items():
                    if key in ["category", "severity"] and log.get(key) != value:
                        skip = True
                        break
                    elif key == "is_error" and log.get("is_error") != value:
                        skip = True
                        break
                    elif key == "confidence" and log.get("confidence", 0) < value:
                        skip = True
                        break
                if skip:
                    continue
                    
            if regex:
                try:
                    pattern = re.compile(regex, re.IGNORECASE)
                    if not pattern.search(log["log"]):
                        continue
                except re.error:
                    pass
                    
            results.append(log)
            
        return results
    
    def add_user(self, username, password, role, projects=None):
        # In production, this calls your actual user management method
        return True
    
    def visualize_results(self, summary):
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

# Initialize session state variables
def init_session_state():
    if 'user_auth' not in st.session_state:
        st.session_state.user_auth = None
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "login"
    if 'classifier' not in st.session_state:
        st.session_state.classifier = LogClassifier()
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'alert_config' not in st.session_state:
        st.session_state.alert_config = {
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
            "thresholds": {
                "error_percentage": 15,
                "high_severity_count": 3,
                "critical_categories": {
                    "authentication failure": 3,
                    "database error": 3,
                    "network error": 5
                }
            }
        }

# Helper function to get dataframe from classified logs
def get_logs_dataframe(classified_logs):
    if not classified_logs:
        return pd.DataFrame()
        
    df = pd.DataFrame(classified_logs)
    # Reorder columns for better display
    columns = ['log', 'category', 'is_error', 'severity', 'confidence', 'timestamp', 'cluster']
    df = df[columns]
    return df

# Convert matplotlib figure to a base64 string
def get_image_base64(fig):
    buf = BytesIO()
    fig.savefig(buf, format="png", bbox_inches='tight')
    buf.seek(0)
    img_str = base64.b64encode(buf.read()).decode('utf-8')
    return img_str

# Login page
def show_login_page():
    st.title("Log Analyzer - Login")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")
        
        if submit_button:
            user_auth = st.session_state.classifier.authenticate_user(username, password)
            if user_auth:
                st.session_state.user_auth = user_auth
                st.session_state.current_page = "dashboard"
                st.success(f"Welcome, {username}! Role: {user_auth['role'].capitalize()}")
                st.rerun()
            else:
                st.error("Invalid username or password")

# Dashboard page
def show_dashboard():
    st.title("Log Analyzer Dashboard")
    
    # Display user info and logout button in the sidebar
    with st.sidebar:
        st.subheader(f"Welcome, {st.session_state.user_auth['username']}")
        st.caption(f"Role: {st.session_state.user_auth['role'].capitalize()}")
        
        # Navigation
        st.subheader("Navigation")
        page = st.radio("Go to:", 
            ["Dashboard", "Log Analysis", "Search Logs", "Configure Alerts", "User Management"],
            index=0 if st.session_state.current_page == "dashboard" else 
                  1 if st.session_state.current_page == "analysis" else
                  2 if st.session_state.current_page == "search" else
                  3 if st.session_state.current_page == "alerts" else
                  4 if st.session_state.current_page == "users" else 0
        )
        
        if page == "Dashboard":
            st.session_state.current_page = "dashboard"
        elif page == "Log Analysis":
            st.session_state.current_page = "analysis"
        elif page == "Search Logs":
            st.session_state.current_page = "search"
        elif page == "Configure Alerts":
            st.session_state.current_page = "alerts"
        elif page == "User Management":
            st.session_state.current_page = "users"
        
        if st.button("Logout"):
            st.session_state.user_auth = None
            st.session_state.current_page = "login"
            st.rerun()
    
    # Permission-based access control for dashboard widgets
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Recent Log Activity")
        st.info("Connect your log sources to see recent activity")
        
        st.subheader("Available Projects")
        if "all" in st.session_state.user_auth["projects"]:
            projects = ["app1", "app2", "app3", "app4"]
        else:
            projects = st.session_state.user_auth["projects"]
            
        st.write(", ".join(projects))
    
    with col2:
        st.subheader("System Status")
        st.success("Log Analyzer is running properly")
        
        # Show alerts only for users with 'alerts' permission
        if st.session_state.classifier.has_permission(st.session_state.user_auth, "alerts"):
            st.subheader("Recent Alerts")
            if st.session_state.analysis_results and "alerts" in st.session_state.analysis_results:
                for alert in st.session_state.analysis_results["alerts"]:
                    if alert["severity"] == "high":
                        st.error(alert["message"])
                    elif alert["severity"] == "medium":
                        st.warning(alert["message"])
                    else:
                        st.info(alert["message"])
            else:
                st.text("No recent alerts")
        
    # Show predictions only for users with 'predictions' permission
    if st.session_state.classifier.has_permission(st.session_state.user_auth, "predictions"):
        st.subheader("Predictive Insights")
        if st.session_state.analysis_results and "predictions" in st.session_state.analysis_results:
            predictions = st.session_state.analysis_results["predictions"]
            
            # Display trend information
            st.info(f"Error trend is {predictions['trend']} (coefficient: {predictions['coefficient']:.3f})")
            
            # Display recommendations
            if "recommendations" in predictions:
                for rec in predictions["recommendations"]:
                    st.warning(rec)
        else:
            st.text("Run log analysis to see predictive insights")

# Log analysis page
def show_log_analysis():
    st.title("Log Analysis")
    
    with st.form("analysis_form"):
        log_file = st.file_uploader("Upload Log File", type=["log", "txt", "csv", "json", "xml"])
        
        project_options = ["app1", "app2", "app3", "app4"] if "all" in st.session_state.user_auth["projects"] else st.session_state.user_auth["projects"]
        project = st.selectbox("Select Project", project_options)
        
        submit_button = st.form_submit_button("Analyze Logs")
        
        if submit_button and log_file is not None:
            # Save uploaded file temporarily
            with open("temp_log_file", "wb") as f:
                f.write(log_file.getbuffer())
            
            # Process logs
            results = st.session_state.classifier.process_logs(
                "temp_log_file", 
                project=project,
                user_auth=st.session_state.user_auth
            )
            
            if "error" in results:
                st.error(results["error"])
            else:
                st.session_state.analysis_results = results
                st.success("Log analysis completed successfully!")
    
    # Display analysis results if available
    if st.session_state.analysis_results:
        results = st.session_state.analysis_results
        
        st.subheader("Analysis Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Logs", results["summary"]["total_logs"])
        col2.metric("Error Percentage", f"{results['summary']['error_percentage']:.2f}%")
        col3.metric("High Severity Issues", results["summary"]["severity"].get("high", 0))
        
        # Display visualizations
        st.subheader("Visualizations")
        fig = st.session_state.classifier.visualize_results(results["summary"])
        st.pyplot(fig)
        
        # Show classified logs in a table
        st.subheader("Classified Logs")
        df = get_logs_dataframe(results["classified_logs"])
        st.dataframe(df, height=300)
        
        # Show remedies section if user has permission
        if st.session_state.classifier.has_permission(st.session_state.user_auth, "remedies") and "remedies" in results:
            st.subheader("Suggested Remedies")
            for remedy in results["remedies"]:
                with st.expander(f"{remedy['issue']} ({remedy['count']} occurrences)"):
                    st.write(remedy["remedy"])
        
        # Show alerts if user has permission
        if st.session_state.classifier.has_permission(st.session_state.user_auth, "alerts") and "alerts" in results:
            st.subheader("Alerts")
            for alert in results["alerts"]:
                if alert["severity"] == "high":
                    st.error(alert["message"])
                elif alert["severity"] == "medium":
                    st.warning(alert["message"])
                else:
                    st.info(alert["message"])
        
        # Show predictions if user has permission
        if st.session_state.classifier.has_permission(st.session_state.user_auth, "predictions") and "predictions" in results:
            st.subheader("Predictive Insights")
            predictions = results["predictions"]
            
            # Create a dataframe for predictions
            if "dates" in predictions and "error_percentage" in predictions:
                pred_df = pd.DataFrame({
                    "Date": predictions["dates"],
                    "Error %": predictions["error_percentage"],
                    "High Severity": predictions["high_severity_count"]
                })
                st.write(pred_df)
            
            # Display recommendations
            if "recommendations" in predictions:
                st.subheader("Recommendations")
                for rec in predictions["recommendations"]:
                    st.warning(rec)

# Search logs page
def show_search_logs():
    st.title("Search Logs")
    
    if not st.session_state.classifier.has_permission(st.session_state.user_auth, "search"):
        st.error("You don't have permission to search logs.")
        return
    
    if not st.session_state.analysis_results or "classified_logs" not in st.session_state.analysis_results:
        st.warning("Please run log analysis first to get logs to search.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        search_query = st.text_input("Search Keyword")
    
    with col2:
        use_regex = st.checkbox("Use Regex")
        if use_regex:
            regex_pattern = st.text_input("Regex Pattern")
        else:
            regex_pattern = None
    
    # Filters
    st.subheader("Filters")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        filter_category = st.selectbox(
            "Category", 
            ["All"] + list(set([log["category"] for log in st.session_state.analysis_results["classified_logs"]]))
        )
    
    with col2:
        filter_severity = st.selectbox("Severity", ["All", "high", "medium", "low"])
    
    with col3:
        filter_is_error = st.selectbox("Error Status", ["All", "Error", "Normal"])
    
    # Create filters dictionary
    filters = {}
    if filter_category != "All":
        filters["category"] = filter_category
    if filter_severity != "All":
        filters["severity"] = filter_severity
    if filter_is_error != "All":
        filters["is_error"] = (filter_is_error == "Error")
    
    if st.button("Search"):
        search_results = st.session_state.classifier.search_logs(
            st.session_state.analysis_results["classified_logs"],
            query=search_query if search_query else None,
            filters=filters if filters else None,
            regex=regex_pattern if regex_pattern else None
        )
        
        st.subheader(f"Search Results ({len(search_results)} logs found)")
        if search_results:
            df = get_logs_dataframe(search_results)
            st.dataframe(df)
        else:
            st.info("No logs match your search criteria.")

# Configure alerts page
def show_configure_alerts():
    st.title("Configure Alerts")
    
    if not st.session_state.classifier.has_permission(st.session_state.user_auth, "alerts"):
        st.error("You don't have permission to configure alerts.")
        return
    
    with st.form("alert_config_form"):
        st.subheader("Alert Configuration")
        
        enabled = st.checkbox("Enable Alerts", value=st.session_state.alert_config["enabled"])
        
        st.subheader("Email Notifications")
        email_enabled = st.checkbox("Enable Email Alerts", value=st.session_state.alert_config["email"]["enabled"])
        
        col1, col2 = st.columns(2)
        with col1:
            smtp_server = st.text_input("SMTP Server", value=st.session_state.alert_config["email"]["smtp_server"])
            smtp_port = st.number_input("SMTP Port", value=st.session_state.alert_config["email"]["smtp_port"])
            username = st.text_input("SMTP Username", value=st.session_state.alert_config["email"]["username"])
        
        with col2:
            password = st.text_input("SMTP Password", type="password", value=st.session_state.alert_config["email"]["password"])
            from_email = st.text_input("From Email", value=st.session_state.alert_config["email"]["from_email"])
            recipients = st.text_input("Recipients (comma separated)", 
                                    value=",".join(st.session_state.alert_config["email"]["recipients"]))
        
        st.subheader("Slack Notifications")
        slack_enabled = st.checkbox("Enable Slack Alerts", value=st.session_state.alert_config["slack"]["enabled"])
        webhook_url = st.text_input("Webhook URL", value=st.session_state.alert_config["slack"]["webhook_url"])
        
        st.subheader("Alert Thresholds")
        col1, col2 = st.columns(2)
        
        with col1:
            error_percentage = st.number_input(
                "Error Percentage Threshold", 
                min_value=0.0, 
                max_value=100.0, 
                value=float(st.session_state.alert_config["thresholds"]["error_percentage"])
            )
        
        with col2:
            high_severity_count = st.number_input(
                "High Severity Count Threshold",
                min_value=0,
                value=int(st.session_state.alert_config["thresholds"]["high_severity_count"])
            )
        
        st.subheader("Category-Specific Thresholds")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            auth_failure_threshold = st.number_input(
                "Authentication Failure Threshold",
                min_value=0,
                value=int(st.session_state.alert_config["thresholds"]["critical_categories"]["authentication failure"])
            )
        
        with col2:
            db_error_threshold = st.number_input(
                "Database Error Threshold",
                min_value=0,
                value=int(st.session_state.alert_config["thresholds"]["critical_categories"]["database error"])
            )
        
        with col3:
            network_error_threshold = st.number_input(
                "Network Error Threshold",
                min_value=0,
                value=int(st.session_state.alert_config["thresholds"]["critical_categories"]["network error"])
            )
        
        if st.form_submit_button("Save Configuration"):
            # Update alert configuration
            st.session_state.alert_config = {
                "enabled": enabled,
                "email": {
                    "enabled": email_enabled,
                    "smtp_server": smtp_server,
                    "smtp_port": int(smtp_port),
                    "username": username,
                    "password": password,
                    "from_email": from_email,
                    "recipients": [r.strip() for r in recipients.split(",") if r.strip()]
                },
                "slack": {
                    "enabled": slack_enabled,
                    "webhook_url": webhook_url
                },
                "thresholds": {
                    "error_percentage": float(error_percentage),
                    "high_severity_count": int(high_severity_count),
                    "critical_categories": {
                        "authentication failure": int(auth_failure_threshold),
                        "database error": int(db_error_threshold),
                        "network error": int(network_error_threshold)
                    }
                }
            }
            
            # Save the configuration
            if st.session_state.classifier.configure_alerts(st.session_state.alert_config):
                st.success("Alert configuration saved successfully!")
            else:
                st.error("Failed to save alert configuration.")

# User management page
def show_user_management():
    st.title("User Management")
    
    # Only admin users can manage users
    if st.session_state.user_auth["role"] != "admin":
        st.error("You don't have permission to access user management.")
        return
    
    st.subheader("Add New User")
    
    with st.form("add_user_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
        
        with col2:
            role = st.selectbox("Role", ["admin", "developer", "manager", "viewer"])
            projects = st.multiselect("Project Access", ["all", "app1", "app2", "app3", "app4"])
        
        if st.form_submit_button("Add User"):
            if username and password:
                if st.session_state.classifier.add_user(username, password, role, projects):
                    st.success(f"User '{username}' added successfully with role '{role}'.")
                else:
                    st.error("Failed to add user.")
            else:
                st.warning("Username and password are required.")

# Main app
def main():
    st.set_page_config(
        page_title="Log Analyzer",
        page_icon="🔍",
        layout="wide"
    )
    
    # Initialize session state
    init_session_state()
    
    # Display appropriate page based on authentication and navigation
    if st.session_state.user_auth is None:
        show_login_page()
    else:
        if st.session_state.current_page == "dashboard":
            show_dashboard()
        elif st.session_state.current_page == "analysis":
            show_log_analysis()
        elif st.session_state.current_page == "search":
            show_search_logs()
        elif st.session_state.current_page == "alerts":
            show_configure_alerts()
        elif st.session_state.current_page == "users":
            show_user_management()
        else:
            show_dashboard()

if __name__ == "__main__":
    main()