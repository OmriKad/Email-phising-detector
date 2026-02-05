"""Streamlit UI for Email Phishing Detector."""
import streamlit as st
import requests
import base64
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, Optional
import plotly.graph_objects as go

# Configuration
BACKEND_URL = "http://localhost:8000"

# Page configuration
st.set_page_config(
    page_title="Email Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Example emails (hardcoded)
EXAMPLE_EMAILS = {
    "Safe Email (Google)": {
        "from": "noreply@google.com",
        "to": "user@example.com",
        "subject": "Welcome to Google",
        "body_plain": "Thank you for signing up for Google services.\n\nBest regards,\nThe Google Team",
        "body_html": """<html><body>
<p>Thank you for signing up for Google services.</p>
<p>Best regards,<br>The Google Team</p>
</body></html>"""
    },
    "Typosquatting Sender": {
        "from": "security@gogle.com",
        "to": "user@example.com",
        "subject": "Account Verification Required",
        "body_plain": "Your account requires immediate verification.\n\nPlease click the link below to verify:\nhttps://gogle.com/verify\n\nSecurity Team",
        "body_html": """<html><body>
<p>Your account requires immediate verification.</p>
<p>Please click the link below to verify:</p>
<p><a href="https://gogle.com/verify">Verify Your Account</a></p>
<p>Security Team</p>
</body></html>"""
    },
    "Suspicious Link (IP Address)": {
        "from": "alert@paypal.com",
        "to": "user@example.com",
        "subject": "Security Alert",
        "body_plain": "We detected unusual activity on your account.\n\nClick here to review: http://192.168.1.1/verify\n\nPayPal Security",
        "body_html": """<html><body>
<p>We detected unusual activity on your account.</p>
<p><a href="http://192.168.1.1/verify">Click here to review</a></p>
<p>PayPal Security</p>
</body></html>"""
    },
    "Multiple Indicators": {
        "from": "urgent@paypa1.com",
        "to": "user@example.com",
        "subject": "URGENT: Account Suspended!",
        "body_plain": "Your account has been suspended immediately due to suspicious activity!\n\nYou must verify your identity now: https://gogle.com/verify\n\nClick here: http://192.168.1.1/login\n\nAct now to avoid permanent suspension!",
        "body_html": """<html><body>
<h2 style="color:red;">URGENT: Account Suspended!</h2>
<p>Your account has been suspended <strong>immediately</strong> due to suspicious activity!</p>
<p>You must verify your identity now:</p>
<p><a href="https://gogle.com/verify">Verify Identity</a></p>
<p><img src="http://192.168.1.1/tracking.png" width="1" height="1"></p>
<p><a href="http://192.168.1.1/login">Click here to restore access</a></p>
<p style="color:red;"><strong>Act now to avoid permanent suspension!</strong></p>
</body></html>"""
    }
}


@st.cache_resource
def check_backend_health() -> bool:
    """Check if FastAPI backend is accessible."""
    try:
        response = requests.get(f"{BACKEND_URL}/api/v1/health", timeout=5)
        return response.status_code == 200
    except Exception:
        return False


def create_gmail_message(from_addr: str, to_addr: str, subject: str, 
                         body_plain: str, body_html: str) -> Dict[str, Any]:
    """Create Gmail API MessagePart format from email fields.
    
    Creates a multipart/alternative message when both plain and HTML bodies exist.
    """
    # Create headers
    headers = [
        {"name": "From", "value": from_addr},
        {"name": "To", "value": to_addr},
        {"name": "Subject", "value": subject}
    ]
    
    # If only one body type exists
    if body_html and not body_plain:
        # HTML only
        body_b64 = base64.urlsafe_b64encode(body_html.encode()).decode().rstrip('=')
        return {
            "id": "streamlit_test",
            "payload": {
                "headers": headers,
                "body": {"data": body_b64},
                "mimeType": "text/html"
            }
        }
    elif body_plain and not body_html:
        # Plain text only
        body_b64 = base64.urlsafe_b64encode(body_plain.encode()).decode().rstrip('=')
        return {
            "id": "streamlit_test",
            "payload": {
                "headers": headers,
                "body": {"data": body_b64},
                "mimeType": "text/plain"
            }
        }
    elif body_plain and body_html:
        # Multipart/alternative (both plain and HTML)
        plain_b64 = base64.urlsafe_b64encode(body_plain.encode()).decode().rstrip('=')
        html_b64 = base64.urlsafe_b64encode(body_html.encode()).decode().rstrip('=')
        
        return {
            "id": "streamlit_test",
            "payload": {
                "headers": headers,
                "mimeType": "multipart/alternative",
                "parts": [
                    {
                        "mimeType": "text/plain",
                        "body": {"data": plain_b64}
                    },
                    {
                        "mimeType": "text/html",
                        "body": {"data": html_b64}
                    }
                ]
            }
        }
    else:
        # No body
        return {
            "id": "streamlit_test",
            "payload": {
                "headers": headers,
                "body": {"data": ""},
                "mimeType": "text/plain"
            }
        }


def create_gauge_chart(risk_score: float) -> go.Figure:
    """Create a gauge chart for risk score with distinct color zones."""
    # Determine color based on score
    if risk_score < 0.33:
        bar_color = "green"
    elif risk_score <= 0.5:
        bar_color = "orange"
    else:
        bar_color = "red"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score * 100,
        title={'text': "Risk Score (%)", 'font': {'size': 20}},
        number={'suffix': "%", 'font': {'size': 40}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1},
            'bar': {'color': bar_color, 'thickness': 0.75},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 33], 'color': 'lightgreen'},
                {'range': [33, 50], 'color': 'lightyellow'},
                {'range': [50, 100], 'color': 'lightcoral'}
            ],
            'threshold': {
                'line': {'color': "black", 'width': 4},
                'thickness': 0.75,
                'value': risk_score * 100
            }
        }
    ))
    
    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=50, b=20),
        paper_bgcolor="white"
    )
    
    return fig


def display_results(result: Dict[str, Any]):
    """Display phishing detection results."""
    st.header("📊 Analysis Results")
    
    risk_score = result['risk_score']
    classification = result['classification']
    indicators = result['indicators']
    message = result['message']
    
    # Gauge chart
    col1, col2 = st.columns([1, 2])
    
    with col1:
        fig = create_gauge_chart(risk_score)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Metrics
        st.subheader("Summary")
        metric_col1, metric_col2, metric_col3 = st.columns(3)
        
        with metric_col1:
            st.metric("Risk Score", f"{risk_score:.1%}")
        
        with metric_col2:
            st.metric("Indicators Found", len(indicators))
        
        with metric_col3:
            st.metric("Status", "⚠️" if len(indicators) > 0 else "✅")
        
        # Classification alert
        st.markdown("---")
        
        if risk_score < 0.33:
            st.success(f"✅ {classification}")
        elif risk_score <= 0.5:
            st.warning(f"⚠️ {classification}")
        else:
            st.error(f"🚨 {classification}")
        
        # Message
        st.info(message)
    
    # Detailed indicators
    if indicators:
        st.markdown("---")
        st.subheader("🔍 Detected Indicators")
        
        # Severity emoji mapping
        severity_emoji = {
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢"
        }
        
        for idx, indicator in enumerate(indicators, 1):
            indicator_type = indicator['type'].replace('_', ' ').title()
            severity = indicator['severity']
            description = indicator['description']
            details = indicator.get('details', {})
            
            emoji = severity_emoji.get(severity, "⚪")
            
            with st.expander(f"{emoji} **{indicator_type}** ({severity.upper()})", expanded=idx <= 2):
                st.write(f"**Description:** {description}")
                
                if details:
                    st.write("**Details:**")
                    st.json(details, expanded=False)


def main():
    """Main Streamlit application."""
    
    # Check backend health
    if not check_backend_health():
        st.error("⚠️ **Backend API is not reachable!**")
        st.info(f"Please ensure the FastAPI server is running on `{BACKEND_URL}`")
        st.code("uv run python main.py", language="bash")
        st.stop()
    
    # Title
    st.title("🛡️ Email Phishing Detector")
    st.markdown("Analyze emails for potential phishing indicators using advanced detection algorithms.")
    
    # Sidebar with examples
    with st.sidebar:
        st.header("📋 Example Emails")
        st.markdown("Load pre-configured example emails for testing:")
        
        for example_name in EXAMPLE_EMAILS.keys():
            if st.button(example_name, key=f"btn_{example_name}", use_container_width=True):
                example = EXAMPLE_EMAILS[example_name]
                st.session_state.from_addr = example['from']
                st.session_state.to_addr = example['to']
                st.session_state.subject = example['subject']
                st.session_state.body_plain = example['body_plain']
                st.session_state.body_html = example['body_html']
                st.rerun()
        
        st.markdown("---")
        st.markdown("### About")
        st.markdown("""
        This tool detects phishing attempts by analyzing:
        - **Sender domain** (typosquatting)
        - **URLs in email** (suspicious links)
        - **Urgent language** patterns
        """)
    
    # Email composition form
    st.header("✉️ Compose Email")
    
    # Initialize session state
    if 'from_addr' not in st.session_state:
        st.session_state.from_addr = ""
    if 'to_addr' not in st.session_state:
        st.session_state.to_addr = ""
    if 'subject' not in st.session_state:
        st.session_state.subject = ""
    if 'body_plain' not in st.session_state:
        st.session_state.body_plain = ""
    if 'body_html' not in st.session_state:
        st.session_state.body_html = ""
    
    # Email fields
    col1, col2 = st.columns(2)
    
    with col1:
        from_addr = st.text_input(
            "From *",
            value=st.session_state.from_addr,
            placeholder="sender@example.com",
            help="Email address of the sender"
        )
    
    with col2:
        to_addr = st.text_input(
            "To",
            value=st.session_state.to_addr,
            placeholder="recipient@example.com",
            help="Email address of the recipient (for realism)"
        )
    
    subject = st.text_input(
        "Subject *",
        value=st.session_state.subject,
        placeholder="Email subject line",
        help="Subject line of the email"
    )
    
    # Body with tabs for Plain Text and HTML
    st.subheader("Body *")
    tab_plain, tab_html = st.tabs(["📝 Plain Text", "🌐 HTML"])
    
    with tab_plain:
        body_plain = st.text_area(
            "Plain Text Body",
            value=st.session_state.body_plain,
            height=300,
            placeholder="Enter the plain text version of the email body...",
            help="Plain text content of the email",
            label_visibility="collapsed"
        )
    
    with tab_html:
        body_html = st.text_area(
            "HTML Body",
            value=st.session_state.body_html,
            height=300,
            placeholder="<html><body><p>Enter HTML version...</p></body></html>",
            help="HTML content of the email (optional)",
            label_visibility="collapsed"
        )
    
    # Update session state
    st.session_state.from_addr = from_addr
    st.session_state.to_addr = to_addr
    st.session_state.subject = subject
    st.session_state.body_plain = body_plain
    st.session_state.body_html = body_html
    
    # Action buttons
    col1, col2 = st.columns([3, 1])
    
    with col1:
        analyze_button = st.button("🔍 Analyze Email", type="primary", use_container_width=True)
    
    with col2:
        if st.button("🗑️ Clear Form", use_container_width=True):
            st.session_state.from_addr = ""
            st.session_state.to_addr = ""
            st.session_state.subject = ""
            st.session_state.body_plain = ""
            st.session_state.body_html = ""
            if 'analysis_result' in st.session_state:
                del st.session_state.analysis_result
            st.rerun()
    
    # Validate and analyze
    if analyze_button:
        # Validation
        if not from_addr:
            st.error("❌ Please enter a 'From' address")
        elif not subject:
            st.error("❌ Please enter a subject line")
        elif not body_plain and not body_html:
            st.error("❌ Please enter email body content (Plain Text or HTML)")
        else:
            # Create Gmail message format
            try:
                gmail_message = create_gmail_message(
                    from_addr=from_addr,
                    to_addr=to_addr or "user@example.com",
                    subject=subject,
                    body_plain=body_plain,
                    body_html=body_html
                )
                
                # Call API
                with st.spinner("Analyzing email for phishing indicators..."):
                    response = requests.post(
                        f"{BACKEND_URL}/api/v1/detect",
                        json=gmail_message,
                        timeout=30
                    )
                
                if response.status_code == 200:
                    result = response.json()
                    st.session_state.analysis_result = result
                else:
                    st.error(f"❌ API Error: {response.status_code} - {response.text}")
            
            except requests.exceptions.Timeout:
                st.error("❌ Request timed out. Please try again.")
            except requests.exceptions.ConnectionError:
                st.error(f"❌ Cannot connect to backend at {BACKEND_URL}")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
    
    # Display results if available
    if 'analysis_result' in st.session_state:
        st.markdown("---")
        display_results(st.session_state.analysis_result)


if __name__ == "__main__":
    main()
