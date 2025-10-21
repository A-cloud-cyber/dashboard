import streamlit as st
import requests
import base64
import json
from datetime import datetime, timedelta
from uuid import uuid4
import urllib3
from streamlit_cookies_manager import EncryptedCookieManager

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cookie manager (use a secure password in production, at least 32 chars)
cookies = EncryptedCookieManager(
    password="your_secure_password_at_least_32_chars",
    prefix="thehive_"
)

if not cookies.ready():
    st.stop()

# CSS for login page - Hide sidebar and improve design
st.markdown("""
<style>
    /* Hide sidebar on login page */
    .css-1d391kg {
        display: none;
    }
    
    /* Hide main menu */
    #MainMenu {
        visibility: hidden;
    }
    
    /* Hide header */
    header {
        visibility: hidden;
    }
    
    /* Hide footer */
    .css-164nlkn {
        visibility: hidden;
    }
    
    .login-container {
        background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
        padding: 2rem;
        border-radius: 15px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
        margin: 2rem auto;
        max-width: 500px;
        color: #ffffff;
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .login-header {
        text-align: center;
        margin-bottom: 2rem;
        font-size: 2.5rem;
        font-weight: bold;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 15px;
    }
    
    .login-form {
        text-align: center;
    }
    
    .login-input {
        width: 100%;
        padding: 0.75rem;
        margin: 0.5rem 0;
        border: 1px solid rgba(255, 255, 255, 0.3);
        border-radius: 8px;
        font-size: 1rem;
        background-color: rgba(255, 255, 255, 0.9);
        color: #333333;
        backdrop-filter: blur(5px);
    }
    
    .login-button {
        width: 100%;
        padding: 0.75rem;
        background: linear-gradient(45deg, #1f77b4, #1565c0);
        color: #ffffff;
        border: none;
        border-radius: 8px;
        font-size: 1rem;
        margin-top: 1rem;
        cursor: pointer;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(31, 119, 180, 0.3);
    }
    
    .login-button:hover {
        background: linear-gradient(45deg, #1565c0, #0d47a1);
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(31, 119, 180, 0.4);
    }
    
    .login-button:disabled {
        background: #cccccc;
        cursor: not-allowed;
        transform: none;
        box-shadow: none;
    }
    
    .success-message {
        background: rgba(76, 175, 80, 0.9);
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        text-align: center;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

def validate_url(url):
    """Validate TheHive URL format"""
    try:
        from urllib.parse import urlparse
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except ValueError:
        return False

def authenticate_thehive_basic(url, username, password, verify_ssl=True):
    """Authenticate using Basic Auth"""
    if not validate_url(url):
        return {'success': False, 'error': 'Invalid URL format. Use http:// or https://'}

    try:
        if url.endswith('/'):
            url = url.rstrip('/')
        
        test_endpoint = f"{url}/api/alert"
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        headers = {
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/json'
        }
        
        params = {'range': '0-5', 'filter': '{}'}
        
        response = requests.get(
            test_endpoint,
            headers=headers,
            params=params,
            verify=verify_ssl,
            timeout=30
        )
        
        if response.status_code == 200:
            try:
                test_data = response.json()
                alert_count = len(test_data) if isinstance(test_data, list) else 0
                
                return {
                    'success': True,
                    'auth_type': 'Basic',
                    'credentials': encoded_credentials,
                    'user': {'username': username, 'name': username.title()},
                    'alert_count': alert_count,
                    'response': response
                }
            except json.JSONDecodeError as e:
                return {
                    'success': True,
                    'auth_type': 'Basic',
                    'credentials': encoded_credentials,
                    'user': {'username': username, 'name': username.title()},
                    'response': response
                }
        else:
            error_detail = response.text[:300] if response.text else "No response body"
            
            return {
                'success': False,
                'error': f'HTTP {response.status_code}: Authentication failed',
                'status_code': response.status_code,
                'response_text': error_detail,
                'response': response
            }
    
    except requests.exceptions.SSLError as e:
        error_msg = f'SSL Error: {str(e)}'
        return {'success': False, 'error': error_msg}
    
    except requests.exceptions.ConnectionError as e:
        error_msg = f'Connection Error: {str(e)}'
        return {'success': False, 'error': error_msg}
    
    except requests.exceptions.RequestException as e:
        error_msg = f'Request Error: {str(e)}'
        return {'success': False, 'error': error_msg}
    
    except Exception as e:
        error_msg = f'Unexpected error: {str(e)}'
        return {'success': False, 'error': error_msg}

def main():
    st.set_page_config(
        page_title="TheHive - Login", 
        layout="centered",
        initial_sidebar_state="collapsed"  # Hide sidebar by default
    )
    
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'auth_info' not in st.session_state:
        st.session_state.auth_info = {}
    if 'session_token' not in st.session_state:
        st.session_state.session_token = None
    if 'last_auth_time' not in st.session_state:
        st.session_state.last_auth_time = None
    
    
    # Header without AI icon
    st.markdown('''
    <div class="login-header">
        TheHive Statistics Dashboard
    </div>
    ''', unsafe_allow_html=True)
    
    st.markdown('<div class="login-form">', unsafe_allow_html=True)
    
    st.markdown("### **TheHive Authentication**")
    
    # Hardcoded URL for security reasons - not shown in UI
    thehive_url = "https://167.86.120.115"
    
    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("👤 Username", placeholder="Enter your username", key="username")
    with col2:
        password = st.text_input("🔑 Password", type="password", placeholder="Enter your password", key="password")
    
    login_disabled = not (username and password)
    
    if st.button("🚀 Connect to TheHive", key="login_button", disabled=login_disabled, use_container_width=True):
        with st.spinner("🔐 Authentication in progress..."):
            # Use SSL bypass by default for internal instances
            verify_setting = False
            auth_result = authenticate_thehive_basic(
                thehive_url, username, password,
                verify_ssl=verify_setting
            )
            
            if auth_result['success']:
                session_token = str(uuid4())
                auth_info = {
                    'thehive_url': thehive_url,
                    'username': username,
                    'user_name': auth_result['user']['name'],
                    'ssl_bypass': True,  # Default to True for internal instances
                    'auth_type': auth_result['auth_type'],
                    'auth_credentials': auth_result['credentials']
                }
                st.session_state.authenticated = True
                st.session_state.auth_info = auth_info
                st.session_state.session_token = session_token
                st.session_state.last_auth_time = datetime.now()
                
                # Save to cookies
                cookies['session_token'] = session_token
                cookies['auth_info'] = json.dumps(auth_info)
                cookies['timestamp'] = datetime.now().isoformat()
                cookies.save()
                
                st.markdown(f'''
                <div class="success-message">
                    ✅ Welcome, {auth_info['user_name']}!<br>
                    🎉 Connection successful - Redirecting to dashboard...
                </div>
                ''', unsafe_allow_html=True)
                
                # Redirect to app.py without session token in URL
                st.markdown("""
                <meta http-equiv="refresh" content="2;url=/app">
                """, unsafe_allow_html=True)
            else:
                st.error(f"❌ **{auth_result['error']}**")
    
    st.markdown('</div></div>', unsafe_allow_html=True)
    
    with st.expander("ℹ️ TheHive Connection Guide", expanded=False):
        st.info("""
        **🔧 Quick Configuration:**
        
        **1. Credentials:**
        - **Username:** Your TheHive username (admin, analyst, etc.)
        - **Password:** Your TheHive password
        - Must have **read access** to alerts and cases
        
        **2. Features:**
        - 📊 **SOC Metrics** automation
        - 📈 **Advanced Dashboards** with visualizations
        - 🔍 **Unified Table** with case and alert data
        
        **💡 Integrated dashboard for optimal analysis of your security data!**
        """)
    
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 1rem 0;'>
        TheHive Dashboard | Security Operations Center
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
