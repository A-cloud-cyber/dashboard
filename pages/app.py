import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import urllib3
from datetime import datetime, timedelta
import numpy as np
import json
from streamlit_cookies_manager import EncryptedCookieManager

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cookie manager (use the same password as in login.py)
cookies = EncryptedCookieManager(
    password="your_secure_password_at_least_32_chars",
    prefix="thehive_"
)

if not cookies.ready():
    st.stop()

# Configuration
st.set_page_config(
    page_title="TheHive - Operational Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 2rem;
        text-align: center;
        border-bottom: 3px solid #3b82f6;
        padding-bottom: 1rem;
    }

    .metric-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 1rem;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }

    .metric-value {
        font-size: 2.5rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }

    .metric-label {
        font-size: 1rem;
        opacity: 0.9;
    }

    .section-header {
        font-size: 1.8rem;
        font-weight: 600;
        color: #374151;
        margin: 2rem 0 1rem 0;
        border-left: 4px solid #3b82f6;
        padding-left: 1rem;
    }

    .kpi-card {
        background: white;
        border-radius: 10px;
        padding: 1.5rem;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        border: 1px solid #e5e7eb;
        margin-bottom: 1rem;
    }

    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.875rem;
        font-weight: 500;
    }

    .status-terminated { background: #dcfce7; color: #166534; }
    .status-in-progress { background: #fef3c7; color: #92400e; }
    .status-untreated { background: #fee2e2; color: #991b1b; }
</style>
""", unsafe_allow_html=True)

def validate_session():
    """Validate if the session is still active"""
    session_token = cookies.get('session_token')
    auth_info_str = cookies.get('auth_info')
    timestamp_str = cookies.get('timestamp')

    if not session_token or not auth_info_str or not timestamp_str:
        st.error("Please log in to access the dashboard.")
        return False

    try:
        auth_info = json.loads(auth_info_str)
        timestamp = datetime.fromisoformat(timestamp_str)
    except Exception as e:
        st.error("Invalid session data. Please log in again.")
        return False

    # Check session timeout (30 minutes)
    if datetime.now() - timestamp > timedelta(minutes=30):
        st.error("Session expired. Please log in again.")
        return False

    # Verify session with API call
    try:
        test_endpoint = f"{auth_info['thehive_url'].rstrip('/')}/api/alert"
        headers = {
            'Authorization': f"Basic {auth_info['auth_credentials']}",
            'Content-Type': 'application/json'
        }
        response = requests.get(test_endpoint, headers=headers, params={'range': '0-1'},
                              verify=not auth_info['ssl_bypass'], timeout=10)
        if response.status_code == 200:
            st.session_state.authenticated = True
            st.session_state.auth_info = auth_info
            st.session_state.session_token = session_token
            st.session_state.last_auth_time = timestamp
            return True
        else:
            st.error("Session validation failed. Please log in again.")
            return False
    except Exception as e:
        st.error(f"Session validation error: {e}")
        return False

# API Functions
@st.cache_data(ttl=300)
def get_alerts(url, auth_credentials, verify_ssl):
    """Fetch alerts from TheHive"""
    try:
        headers = {
            "Authorization": f"Basic {auth_credentials}",
            "Content-Type": "application/json"
        }
        response = requests.get(f"{url}/api/alert?range=0-500", headers=headers, verify=verify_ssl, timeout=10)
        return response.json() if response.status_code == 200 else []
    except Exception as e:
        st.error(f"Alert API Error: {e}")
        return []

@st.cache_data(ttl=300)
def get_cases(url, auth_credentials, verify_ssl):
    """Fetch cases from TheHive"""
    try:
        headers = {
            "Authorization": f"Basic {auth_credentials}",
            "Content-Type": "application/json"
        }
        response = requests.get(f"{url}/api/case?range=0-500", headers=headers, verify=verify_ssl, timeout=10)
        return response.json() if response.status_code == 200 else []
    except Exception as e:
        st.error(f"Case API Error: {e}")
        return []

# Data Processing
def process_operational_data(alerts, cases):
    """Process data for detailed operational tracking"""
    operational_data = []

    cases_dict = {case.get('_id'): case for case in cases}

    for alert in alerts:
        alert_info = {
            'alert_id': alert.get('_id', ''),
            'alert_title': alert.get('title', 'Title not available'),
            'sourceRef': alert.get('sourceRef', 'N/A'),
            'alert_status': alert.get('status', 'New'),
            'severity': alert.get('severity', 1),
            'type': alert.get('type', ''),
            'source': alert.get('source', 'Unknown'),
            'case_id': alert.get('case', ''),
        }

        # Alert creation date
        if alert.get('createdAt'):
            alert_info['alert_created_at'] = pd.to_datetime(alert.get('createdAt'), unit='ms')
        else:
            alert_info['alert_created_at'] = pd.to_datetime('2025-09-23 12:40:00')

        # Custom timestamps
        custom_fields = alert.get('customFields', {})

        received_time_data = custom_fields.get('alert-received-time', {})
        if received_time_data and 'date' in received_time_data:
            alert_info['alert_received_time'] = pd.to_datetime(received_time_data['date'], unit='ms')
        else:
            alert_info['alert_received_time'] = pd.to_datetime('2025-09-23 12:40:00')

        processing_time_data = custom_fields.get('processing-start-time', {})
        if processing_time_data and 'date' in processing_time_data:
            alert_info['processing_start_time'] = pd.to_datetime(processing_time_data['date'], unit='ms')
        else:
            alert_info['processing_start_time'] = pd.to_datetime('2025-09-23 12:40:00')

        # Response time calculation
        if alert_info['alert_received_time'] and alert_info['processing_start_time']:
            alert_info['response_time_minutes'] = (
                alert_info['processing_start_time'] - alert_info['alert_received_time']
            ).total_seconds() / 60
        else:
            alert_info['response_time_minutes'] = None

        # Associated case information
        case_id = alert_info['case_id']
        if case_id and case_id in cases_dict:
            case = cases_dict[case_id]
            alert_info.update({
                'case_title': case.get('title', ''),
                'case_status': case.get('status', 'Open'),
                'assigned_to': case.get('assignee', case.get('owner', 'Unassigned')),
                'case_created_at': pd.to_datetime(case.get('createdAt'), unit='ms') if case.get('createdAt') else pd.to_datetime('2025-09-23 12:40:00'),
                'case_updated_at': pd.to_datetime(case.get('updatedAt'), unit='ms') if case.get('updatedAt') else None,
                'case_closed_at': pd.to_datetime(case.get('endDate'), unit='ms') if case.get('endDate') else None,
            })

            # Resolution time
            if alert_info['case_closed_at'] and alert_info['case_created_at']:
                alert_info['resolution_time_hours'] = (
                    alert_info['case_closed_at'] - alert_info['case_created_at']
                ).total_seconds() / 3600
            else:
                alert_info['resolution_time_hours'] = None
        else:
            alert_info.update({
                'case_title': 'No case created',
                'case_status': 'N/A',
                'assigned_to': 'Unassigned',
                'case_created_at': None,
                'case_updated_at': None,
                'case_closed_at': None,
                'resolution_time_hours': None,
            })

        # Operational status
        if alert_info['case_status'] in ['Resolved', 'Closed']:
            alert_info['operational_status'] = 'Terminated'
        elif alert_info['case_id'] and alert_info['case_status'] in ['InProgress', 'Open']:
            alert_info['operational_status'] = 'In Progress'
        elif alert_info['case_id']:
            alert_info['operational_status'] = 'In Progress'
        else:
            alert_info['operational_status'] = 'Untreated'

        operational_data.append(alert_info)

    return pd.DataFrame(operational_data)

# KPI and Visualizations
def create_modern_kpi_dashboard(df):
    """Modern KPI dashboard"""
    if df.empty:
        st.warning("No data available for KPIs")
        return

    st.markdown('<div class="section-header">Key Performance Indicators Dashboard</div>', unsafe_allow_html=True)

    # Calculate metrics
    total_alerts = len(df)
    untreated = len(df[df['operational_status'] == 'Untreated'])
    in_progress = len(df[df['operational_status'] == 'In Progress'])
    terminated = len(df[df['operational_status'] == 'Terminated'])
    avg_response = df['response_time_minutes'].mean()
    avg_resolution = df['resolution_time_hours'].mean()

    # First row of KPIs
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
            <div class="metric-value">{total_alerts}</div>
            <div class="metric-label">Total Alerts</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        pct_untreated = (untreated/total_alerts*100) if total_alerts > 0 else 0
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
            <div class="metric-value">{untreated}</div>
            <div class="metric-label">Untreated ({pct_untreated:.1f}%)</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        pct_in_progress = (in_progress/total_alerts*100) if total_alerts > 0 else 0
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);">
            <div class="metric-value">{in_progress}</div>
            <div class="metric-label">In Progress ({pct_in_progress:.1f}%)</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        pct_terminated = (terminated/total_alerts*100) if total_alerts > 0 else 0
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);">
            <div class="metric-value">{terminated}</div>
            <div class="metric-label">Terminated ({pct_terminated:.1f}%)</div>
        </div>
        """, unsafe_allow_html=True)

    # Second row - Performance metrics
    col5, col6 = st.columns(2)

    with col5:
        response_text = f"{avg_response:.1f} min" if pd.notna(avg_response) else "N/A"
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
            <div class="metric-value">{response_text}</div>
            <div class="metric-label">Average Response Time</div>
        </div>
        """, unsafe_allow_html=True)

    with col6:
        resolution_text = f"{avg_resolution:.1f} h" if pd.notna(avg_resolution) else "N/A"
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
            <div class="metric-value">{resolution_text}</div>
            <div class="metric-label">Average Resolution Time</div>
        </div>
        """, unsafe_allow_html=True)

def create_advanced_status_chart(df):
    """Advanced status chart"""
    if df.empty:
        return

    status_counts = df['operational_status'].value_counts()

    # Modern donut chart
    fig = go.Figure(data=[go.Pie(
        labels=status_counts.index,
        values=status_counts.values,
        hole=.5,
        marker_colors=['#ef4444', '#f59e0b', '#10b981']
    )])

    fig.update_traces(
        textposition='inside',
        textinfo='percent+label',
        textfont_size=14,
        textfont_color="white"
    )

    fig.update_layout(
        title={
            'text': "Operational Status Distribution",
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#1f2937'}
        },
        font=dict(size=12),
        height=400,
        margin=dict(t=80, b=20, l=20, r=20)
    )

    st.plotly_chart(fig, use_container_width=True)

def create_response_time_dashboard(df):
    """Response time dashboard"""
    response_data = df[df['response_time_minutes'].notna()].copy()

    if response_data.empty:
        st.info("No response time data available")
        return

    # Histogram with density curve
    fig = make_subplots(specs=[[{"secondary_y": True}]])

    # Histogram
    fig.add_trace(
        go.Histogram(
            x=response_data['response_time_minutes'],
            nbinsx=25,
            name="Distribution",
            marker_color='rgba(59, 130, 246, 0.7)',
            yaxis='y'
        ),
        secondary_y=False,
    )

    # Statistics
    avg_response = response_data['response_time_minutes'].mean()
    median_response = response_data['response_time_minutes'].median()

    # Reference lines
    fig.add_vline(x=avg_response, line_dash="dash", line_color="#ef4444", line_width=2,
                  annotation_text=f"Average: {avg_response:.1f} min")
    fig.add_vline(x=median_response, line_dash="dot", line_color="#10b981", line_width=2,
                  annotation_text=f"Median: {median_response:.1f} min")
    fig.add_vline(x=30, line_dash="solid", line_color="#f59e0b", line_width=2,
                  annotation_text="SLA: 30 min")

    fig.update_layout(
        title={
            'text': "Response Time Analysis",
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#1f2937'}
        },
        xaxis_title="Response Time (minutes)",
        yaxis_title="Number of Alerts",
        height=450,
        margin=dict(t=80, b=60, l=60, r=60)
    )

    st.plotly_chart(fig, use_container_width=True)

def create_assignment_performance_dashboard(df):
    """Assignment performance dashboard"""
    assigned_data = df[df['assigned_to'] != 'Unassigned'].copy()

    if assigned_data.empty:
        st.info("No assignment data available")
        return

    # Analysis by assignee
    assignment_stats = assigned_data.groupby('assigned_to').agg({
        'alert_id': 'count',
        'operational_status': lambda x: (x == 'Terminated').sum(),
        'resolution_time_hours': 'mean',
        'response_time_minutes': 'mean'
    }).reset_index()

    assignment_stats.columns = ['Assignee', 'Total_Cases', 'Cases_Terminated', 'Avg_Resolution_Time', 'Avg_Response_Time']

    # Ensure numeric types and fill NaN values
    assignment_stats['Avg_Resolution_Time'] = pd.to_numeric(assignment_stats['Avg_Resolution_Time'], errors='coerce').fillna(0)
    assignment_stats['Avg_Response_Time'] = pd.to_numeric(assignment_stats['Avg_Response_Time'], errors='coerce').fillna(0)

    assignment_stats['Completion_Rate'] = (assignment_stats['Cases_Terminated'] / assignment_stats['Total_Cases']) * 100
    assignment_stats['Cases_In_Progress'] = assignment_stats['Total_Cases'] - assignment_stats['Cases_Terminated']

    # Combined performance chart
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Distribution by Assignee', 'Completion Rate',
                       'Average Resolution Time', 'Average Response Time'),
        specs=[[{"type": "bar"}, {"type": "bar"}],
               [{"type": "bar"}, {"type": "bar"}]]
    )

    # Chart 1: Stacked bars
    fig.add_trace(
        go.Bar(name='Terminated', x=assignment_stats['Assignee'], y=assignment_stats['Cases_Terminated'],
               marker_color='#10b981'),
        row=1, col=1
    )
    fig.add_trace(
        go.Bar(name='In Progress', x=assignment_stats['Assignee'], y=assignment_stats['Cases_In_Progress'],
               marker_color='#f59e0b'),
        row=1, col=1
    )

    # Chart 2: Completion rate
    fig.add_trace(
        go.Bar(x=assignment_stats['Assignee'], y=assignment_stats['Completion_Rate'],
               marker_color='#3b82f6', showlegend=False),
        row=1, col=2
    )

    # Chart 3: Resolution time
    fig.add_trace(
        go.Bar(x=assignment_stats['Assignee'], y=assignment_stats['Avg_Resolution_Time'],
               marker_color='#8b5cf6', showlegend=False),
        row=2, col=1
    )

    # Chart 4: Response time
    fig.add_trace(
        go.Bar(x=assignment_stats['Assignee'], y=assignment_stats['Avg_Response_Time'],
               marker_color='#ec4899', showlegend=False),
        row=2, col=2
    )

    fig.update_layout(
        height=700,
        title_text="Assignee Performance Dashboard",
        title_x=0.5,
        barmode='stack'
    )

    fig.update_yaxes(title_text="Number of Cases", row=1, col=1)
    fig.update_yaxes(title_text="Rate (%)", row=1, col=2)
    fig.update_yaxes(title_text="Hours", row=2, col=1)
    fig.update_yaxes(title_text="Minutes", row=2, col=2)

    st.plotly_chart(fig, use_container_width=True)

    # Performance table
    st.markdown('<div class="section-header">Detailed Assignee Performance</div>', unsafe_allow_html=True)

    # Format DataFrame for display
    display_stats = assignment_stats.copy()
    display_stats['Avg_Resolution_Time'] = display_stats['Avg_Resolution_Time'].round(1)
    display_stats['Avg_Response_Time'] = display_stats['Avg_Response_Time'].round(1)
    display_stats['Completion_Rate'] = display_stats['Completion_Rate'].round(1)

    st.dataframe(
        display_stats,
        column_config={
            "Assignee": "Assignee",
            "Total_Cases": "Total Cases",
            "Cases_Terminated": "Cases Terminated",
            "Completion_Rate": st.column_config.ProgressColumn(
                "Completion Rate (%)",
                min_value=0,
                max_value=100,
                format="%.1f%%"
            ),
            "Avg_Resolution_Time": st.column_config.NumberColumn(
                "Avg Resolution Time (h)",
                format="%.1f"
            ),
            "Avg_Response_Time": st.column_config.NumberColumn(
                "Avg Response Time (min)",
                format="%.1f"
            )
        },
        use_container_width=True,
        hide_index=True
    )

def create_timeline_dashboard(df):
    """Advanced timeline dashboard"""
    timeline_data = df[df['alert_created_at'].notna()].copy()

    if timeline_data.empty:
        st.info("No temporal data available")
        return

    # Analysis by day
    timeline_data['date'] = timeline_data['alert_created_at'].dt.date
    timeline_data['hour'] = timeline_data['alert_created_at'].dt.hour

    daily_stats = timeline_data.groupby('date').agg({
        'alert_id': 'count',
        'response_time_minutes': 'mean',
        'operational_status': lambda x: (x == 'Terminated').sum(),
        'resolution_time_hours': 'mean'
    }).reset_index()

    daily_stats.columns = ['Date', 'Nb_Alerts', 'Avg_Response', 'Nb_Terminated', 'Avg_Resolution']

    # Combined temporal chart
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Alert Volume by Day', 'Average Response Time',
                       'Hourly Distribution', 'Resolution Trend'),
        specs=[[{"secondary_y": False}, {"secondary_y": False}],
               [{"secondary_y": False}, {"secondary_y": False}]]
    )

    # Volume by day
    fig.add_trace(
        go.Bar(x=daily_stats['Date'], y=daily_stats['Nb_Alerts'],
               marker_color='#3b82f6', name='Alerts'),
        row=1, col=1
    )

    # Response time
    fig.add_trace(
        go.Scatter(x=daily_stats['Date'], y=daily_stats['Avg_Response'],
                  mode='lines+markers', line=dict(color='#ef4444', width=3),
                  name='Avg Response'),
        row=1, col=2
    )

    # Hourly distribution
    hourly_dist = timeline_data.groupby('hour').size().reset_index()
    hourly_dist.columns = ['Hour', 'Count']

    fig.add_trace(
        go.Bar(x=hourly_dist['Hour'], y=hourly_dist['Count'],
               marker_color='#10b981', name='By Hour'),
        row=2, col=1
    )

    # Resolution trend
    fig.add_trace(
        go.Scatter(x=daily_stats['Date'], y=daily_stats['Nb_Terminated'],
                  mode='lines+markers', line=dict(color='#8b5cf6', width=3),
                  name='Cases Terminated'),
        row=2, col=2
    )

    fig.update_layout(
        height=700,
        title_text="Complete Temporal Analysis",
        title_x=0.5,
        showlegend=False
    )

    st.plotly_chart(fig, use_container_width=True)

def main():
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'auth_info' not in st.session_state:
        st.session_state.auth_info = {}
    if 'session_token' not in st.session_state:
        st.session_state.session_token = None
    if 'last_auth_time' not in st.session_state:
        st.session_state.last_auth_time = None
    if 'filters' not in st.session_state:
        st.session_state.filters = {
            'days_filter': 30,
            'status_filter': ['Untreated', 'In Progress', 'Terminated']
        }
    if 'df' not in st.session_state:
        st.session_state.df = None

    # Validate session
    if not validate_session():
        st.markdown("""
        <meta http-equiv="refresh" content="2;url=/login">
        """, unsafe_allow_html=True)
        st.stop()

    # Sidebar with user info and controls
    with st.sidebar:
        auth_info = st.session_state.auth_info
        st.markdown(f"### 👋 **{auth_info.get('user_name', auth_info.get('username', 'User'))}**")
        st.markdown("---")

        st.header("Configuration")

        if st.button("Refresh Data", type="primary", use_container_width=True):
            st.cache_data.clear()
            st.session_state.df = None
            st.rerun()

        st.subheader("Filters")
        days_filter = st.selectbox("Analysis Period", [7, 14, 30, 90], index=2, key="days_filter")
        st.session_state.filters['days_filter'] = days_filter

        status_filter = st.multiselect(
            "Operational Status",
            ['Untreated', 'In Progress', 'Terminated'],
            default=st.session_state.filters['status_filter'],
            key="status_filter"
        )
        st.session_state.filters['status_filter'] = status_filter

        st.markdown("---")
        if st.button("🚪 Logout", type="secondary", use_container_width=True):
            cookies['session_token'] = ''
            cookies['auth_info'] = ''
            cookies['timestamp'] = ''
            cookies.save()
            st.session_state.clear()
            st.success("👋 Logged out successfully!")
            st.markdown("""
            <meta http-equiv="refresh" content="2;url=/">
            """, unsafe_allow_html=True)
            st.stop()

    st.markdown('<div class="main-header">TheHive Operational Dashboard</div>', unsafe_allow_html=True)

    # Load data
    auth_info = st.session_state.auth_info
    if st.session_state.df is None:
        with st.spinner("Loading operational data..."):
            alerts = get_alerts(
                auth_info['thehive_url'], auth_info['auth_credentials'],
                verify_ssl=not auth_info['ssl_bypass']
            )
            cases = get_cases(
                auth_info['thehive_url'], auth_info['auth_credentials'],
                verify_ssl=not auth_info['ssl_bypass']
            )

            df = process_operational_data(alerts, cases)
            st.session_state.df = df
            st.success(f"✅ Loaded **{len(df):,} alerts**")
    else:
        df = st.session_state.df
        st.info(f"📊 Using cached data: **{len(df):,} alerts**")

    # Filter data
    if not df.empty:
        cutoff_date = datetime.now() - timedelta(days=st.session_state.filters['days_filter'])
        df = df[
            (df['alert_created_at'].isna()) |
            (df['alert_created_at'] >= cutoff_date)
        ]

        if st.session_state.filters['status_filter']:
            df = df[df['operational_status'].isin(st.session_state.filters['status_filter'])]

    # Main dashboard
    create_modern_kpi_dashboard(df)

    st.divider()

    # Main charts
    col1, col2 = st.columns(2)

    with col1:
        create_advanced_status_chart(df)

    with col2:
        create_response_time_dashboard(df)

    st.divider()

    # Assignee performance
    st.markdown('<div class="section-header">Performance Analysis</div>', unsafe_allow_html=True)
    create_assignment_performance_dashboard(df)

    st.divider()

    # Temporal analysis
    st.markdown('<div class="section-header">Temporal Analysis</div>', unsafe_allow_html=True)
    create_timeline_dashboard(df)

    st.divider()

    # Detailed table
    st.markdown('<div class="section-header">Detailed Data</div>', unsafe_allow_html=True)

    if not df.empty:
        # Colonnes à afficher (avec alert_received_time)
        display_columns = [
            'alert_title', 'sourceRef', 'alert_created_at',
            'alert_received_time', 'response_time_minutes',
            'resolution_time_hours', 'assigned_to',
            'case_closed_at', 'operational_status'
        ]

        available_columns = [col for col in display_columns if col in df.columns]

        column_config = {
            "alert_title": "Alert Title",
            "sourceRef": "Source Ref",
            "alert_created_at": st.column_config.DatetimeColumn(
                "Created At",
                format="DD/MM/YYYY HH:mm",
                help="Timestamp when the alert was created in thehive"
            ),
            "alert_received_time": st.column_config.DatetimeColumn(
                "Received At",
                format="DD/MM/YYYY HH:mm",
                help="Timestamp when the alert was received by Elastic stack"
            ),
            "response_time_minutes": st.column_config.NumberColumn(
                "Response Time (min)",
                format="%.1f",
                help="Time between alert reception and processing start"
            ),
            "resolution_time_hours": st.column_config.NumberColumn(
                "Resolution Time (h)",
                format="%.1f",
                help="Total time from case creation to closure"
            ),
            "assigned_to": "Assigned To",
            "case_closed_at": st.column_config.DatetimeColumn(
                "Terminated At",
                format="DD/MM/YYYY HH:mm"
            ),
            "operational_status": st.column_config.SelectboxColumn(
                "Operational Status",
                options=['Untreated', 'In Progress', 'Terminated']
            )
        }

        def style_status(val):
            if pd.isna(val) or val == 'N/A':
                return ''
            val_str = str(val)
            if val_str == 'Terminated':
                return 'background-color: #dcfce7; color: #166534; font-weight: bold'
            elif val_str == 'In Progress':
                return 'background-color: #fef3c7; color: #92400e; font-weight: bold'
            elif val_str == 'Untreated':
                return 'background-color: #fee2e2; color: #991b1b; font-weight: bold'
            return ''

        styled_df = df[available_columns].head(100).style.applymap(style_status, subset=['operational_status'])
        st.dataframe(
            styled_df,
            column_config=column_config,
            use_container_width=True,
            hide_index=True
        )

        # Summary statistics
        st.markdown('<div class="section-header">Summary Statistics</div>', unsafe_allow_html=True)

        col_stat1, col_stat2, col_stat3, col_stat4 = st.columns(4)

        with col_stat1:
            if df['response_time_minutes'].notna().any():
                avg_response = df['response_time_minutes'].mean()
                median_response = df['response_time_minutes'].median()
                st.markdown(f"""
                <div class="kpi-card">
                    <h4 style="margin-top:0; color:#374151;">Response Time</h4>
                    <p><strong>Average:</strong> {avg_response:.1f} min</p>
                    <p><strong>Median:</strong> {median_response:.1f} min</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="kpi-card">
                    <h4 style="margin-top:0; color:#374151;">Response Time</h4>
                    <p>No data available</p>
                </div>
                """, unsafe_allow_html=True)

        with col_stat2:
            if df['resolution_time_hours'].notna().any():
                avg_resolution = df['resolution_time_hours'].mean()
                median_resolution = df['resolution_time_hours'].median()
                st.markdown(f"""
                <div class="kpi-card">
                    <h4 style="margin-top:0; color:#374151;">Resolution Time</h4>
                    <p><strong>Average:</strong> {avg_resolution:.1f} h</p>
                    <p><strong>Median:</strong> {median_resolution:.1f} h</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="kpi-card">
                    <h4 style="margin-top:0; color:#374151;">Resolution Time</h4>
                    <p>No data available</p>
                </div>
                """, unsafe_allow_html=True)

        with col_stat3:
            completion_rate = (len(df[df['operational_status'] == 'Terminated']) / len(df)) * 100 if len(df) > 0 else 0
            sla_compliance = len(df[(df['response_time_minutes'] <= 30) & df['response_time_minutes'].notna()]) / len(df[df['response_time_minutes'].notna()]) * 100 if len(df[df['response_time_minutes'].notna()]) > 0 else 0
            st.markdown(f"""
            <div class="kpi-card">
                <h4 style="margin-top:0; color:#374151;">Performance Rates</h4>
                <p><strong>Completion:</strong> {completion_rate:.1f}%</p>
                <p><strong>SLA Compliance:</strong> {sla_compliance:.1f}%</p>
            </div>
            """, unsafe_allow_html=True)

        with col_stat4:
            total_sources = df['source'].nunique()
            most_frequent_source = df['source'].value_counts().index[0] if not df['source'].empty else "N/A"
            severity_avg = df['severity'].mean() if df['severity'].notna().any() else 0
            st.markdown(f"""
            <div class="kpi-card">
                <h4 style="margin-top:0; color:#374151;">Sources & Severity</h4>
                <p><strong>Unique Sources:</strong> {total_sources}</p>
                <p><strong>Main Source:</strong> {most_frequent_source}</p>
                <p><strong>Average Severity:</strong> {severity_avg:.1f}</p>
            </div>
            """, unsafe_allow_html=True)

    else:
        st.info("No data to display with the selected filters")
        st.markdown("""
        <div style="text-align: center; padding: 2rem;">
            <h3>Suggestions:</h3>
            <ul style="text-align: left; display: inline-block;">
                <li>Check TheHive connectivity</li>
                <li>Adjust the period filter</li>
                <li>Modify status selections</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    # Informative footer
    st.divider()

    info_col1, info_col2, info_col3 = st.columns(3)

    with info_col1:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: #f8fafc; border-radius: 8px;">
            <h5 style="margin:0; color:#64748b;">Last Update</h5>
            <p style="margin:0; color:#374151;">{datetime.now().strftime('%d/%m/%Y at %H:%M:%S')}</p>
        </div>
        """, unsafe_allow_html=True)

    with info_col2:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: #f8fafc; border-radius: 8px;">
            <h5 style="margin:0; color:#64748b;">Analysis Period</h5>
            <p style="margin:0; color:#374151;">Last {st.session_state.filters['days_filter']} days</p>
        </div>
        """, unsafe_allow_html=True)

    with info_col3:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: #f8fafc; border-radius: 8px;">
            <h5 style="margin:0; color:#64748b;">Total Analyzed</h5>
            <p style="margin:0; color:#374151;">{len(df)} alerts</p>
        </div>
        """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
