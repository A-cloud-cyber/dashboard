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
try:
    import tzlocal
    _GET_LOCAL_TZ = tzlocal.get_localzone
except Exception:
    # Fallback: use system local timezone info via datetime
    from datetime import datetime as _dt_datetime
    _GET_LOCAL_TZ = lambda: _dt_datetime.now().astimezone().tzinfo
from streamlit_cookies_manager import EncryptedCookieManager
try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

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
    def convert_severity_to_priority(severity):
        severity_map = {
            4: 'P1',  # Critique (4 -> P1)
            3: 'P2',  # Haute (3 -> P2)
            2: 'P3',  # Moyenne (2 -> P3)
            1: 'P4'   # Basse (1 -> P4)
        }
        return severity_map.get(severity, 'N/A')

    operational_data = []
    cases_dict = {case.get('_id'): case for case in cases}

    for alert in alerts:
        alert_info = {
            'alert_id': alert.get('_id', ''),
            'alert_title': alert.get('title', 'Title not available'),
            'sourceRef': alert.get('sourceRef', 'N/A'),
            'alert_status': alert.get('status', 'New'),
            'severity': convert_severity_to_priority(alert.get('severity', 1)),  # Conversion ici
            'type': alert.get('type', ''),
            'source': alert.get('source', 'Unknown'),
            'case_id': alert.get('case', ''),
            # Correction de l'extraction du mode de détection
            'mode_detection': alert.get('customFields', {}).get('mode-detection', {}).get('string', 'N/A')
        }

        # Alert creation date (convert from UTC to local time directly)
        if alert.get('createdAt'):
            ts = pd.to_datetime(alert.get('createdAt'), unit='ms')
            alert_info['alert_created_at'] = ts + pd.Timedelta(hours=1)  # Add 1 hour to match TheHive UI
        else:
            alert_info['alert_created_at'] = pd.NaT

        # Custom timestamps
        custom_fields = alert.get('customFields', {}) or {}

        received_time_data = custom_fields.get('alert-received-time', {})
        if received_time_data and 'date' in received_time_data:
            ts = pd.to_datetime(received_time_data['date'], unit='ms')
            alert_info['alert_received_time'] = ts + pd.Timedelta(hours=1)  # Add 1 hour to match TheHive UI
        else:
            alert_info['alert_received_time'] = pd.NaT

        processing_time_data = custom_fields.get('processing-start-time', {})
        if processing_time_data and 'date' in processing_time_data:
            ts = pd.to_datetime(processing_time_data['date'], unit='ms')
            alert_info['processing_start_time'] = ts + pd.Timedelta(hours=1)  # Adjust as needed
        else:
            alert_info['processing_start_time'] = pd.NaT  # Default to NaT if not found

        # Alert generated time (real incident time)
        generated_time_data = custom_fields.get('alert-generated-time', {})
        if generated_time_data and 'date' in generated_time_data:
            ts = pd.to_datetime(generated_time_data['date'], unit='ms')
            alert_info['alert_generated_time'] = ts + pd.Timedelta(hours=1)
        else:
            alert_info['alert_generated_time'] = pd.NaT

        # Response time calculation (existing): created_at - received_at
        if pd.notna(alert_info['alert_received_time']) and pd.notna(alert_info['alert_created_at']):
            try:
                alert_info['response_time_minutes'] = (
                    alert_info['alert_created_at'] - alert_info['alert_received_time']
                ).total_seconds() / 60
            except Exception:
                alert_info['response_time_minutes'] = None
        else:
            alert_info['response_time_minutes'] = None

        # Takeover time (KPI 1): processing_start_time - alert_received_time (minutes)
        if pd.notna(alert_info['alert_received_time']) and pd.notna(alert_info['processing_start_time']):
            try:
                alert_info['takeover_time_minutes'] = (
                    alert_info['processing_start_time'] - alert_info['alert_received_time']
                ).total_seconds() / 60
            except Exception:
                alert_info['takeover_time_minutes'] = None
        else:
            alert_info['takeover_time_minutes'] = None

        # MTTD calculation (KPI 2): received_time - generated_time (minutes)
        if pd.notna(alert_info['alert_generated_time']) and pd.notna(alert_info['alert_received_time']):
            try:
                alert_info['mttd_minutes'] = (
                    alert_info['alert_received_time'] - alert_info['alert_generated_time']
                ).total_seconds() / 60
            except Exception:
                alert_info['mttd_minutes'] = None
        else:
            alert_info['mttd_minutes'] = None

        # Associated case information
        case_id = alert_info['case_id']
        if case_id and case_id in cases_dict:
            case = cases_dict[case_id]

            # Add resolutionStatus to alert_info
            alert_info['resolutionStatus'] = case.get('resolutionStatus', '')

            # Update false_positive detection logic
            alert_info['false_positive'] = False
            if case.get('resolutionStatus', '').lower() == 'falsepositive':
                alert_info['false_positive'] = True

            # Convert case timestamps - ensure all timestamps are tz-naive for consistent calculations
            if case.get('createdAt'):
                ts = pd.to_datetime(case.get('createdAt'), unit='ms')
                case_created_at = ts + pd.Timedelta(hours=1)
            else:
                case_created_at = pd.NaT

            if case.get('updatedAt'):
                ts = pd.to_datetime(case.get('updatedAt'), unit='ms')
                case_updated_at = ts + pd.Timedelta(hours=1)
            else:
                case_updated_at = pd.NaT

            if case.get('endDate'):
                ts = pd.to_datetime(case.get('endDate'), unit='ms')
                case_closed_at = ts + pd.Timedelta(hours=1)
            else:
                case_closed_at = pd.NaT

            alert_info.update({
                'case_title': case.get('title', ''),
                'case_status': case.get('status', 'Open'),
                'assigned_to': case.get('assignee', case.get('owner', 'Unassigned')),
                'case_created_at': case_created_at,
                'case_updated_at': case_updated_at,
                'case_closed_at': case_closed_at,
            })

            # If false_positive is not provided on the alert, check case custom fields or tags
            case_custom = case.get('customFields', {}) or {}
            # common variations
            case_fp = case_custom.get('false_positive') if isinstance(case_custom, dict) else None
            if not alert_info.get('false_positive') and case_fp is not None:
                alert_info['false_positive'] = case_fp
            # also check tags or labels which some instances use
            tags = case.get('tags') or case.get('labels') or []
            try:
                if (not alert_info.get('false_positive')) and isinstance(tags, (list, tuple)) and any(str(t).lower() in ['false_positive', 'false-positive', 'fp', 'false positive', 'faux_positif', 'faux positif'] for t in tags):
                    alert_info['false_positive'] = True
            except Exception:
                pass

            # Resolution time (existing)
            if pd.notna(alert_info['case_closed_at']) and pd.notna(alert_info['case_created_at']):
                try:
                    alert_info['resolution_time_hours'] = (
                        alert_info['case_closed_at'] - alert_info['case_created_at']
                    ).total_seconds() / 3600
                except Exception:
                    alert_info['resolution_time_hours'] = None
            else:
                alert_info['resolution_time_hours'] = None

            # MTTR (KPI 3): time between received_at and terminated_at (hours)
            if pd.notna(alert_info['alert_received_time']) and pd.notna(alert_info['case_closed_at']):
                try:
                    alert_info['mttr_hours'] = (
                        alert_info['case_closed_at'] - alert_info['alert_received_time']
                    ).total_seconds() / 3600
                    alert_info['mttr_minutes'] = alert_info['mttr_hours'] * 60 if alert_info['mttr_hours'] is not None else None
                except Exception:
                    alert_info['mttr_hours'] = None
                    alert_info['mttr_minutes'] = None
            else:
                alert_info['mttr_hours'] = None
                alert_info['mttr_minutes'] = None
        else:
            alert_info.update({
                'case_title': 'No case created',
                'case_status': 'N/A',
                'assigned_to': 'Unassigned',
                'case_created_at': pd.NaT,
                'case_updated_at': pd.NaT,
                'case_closed_at': pd.NaT,
                'resolution_time_hours': None,
                'mttr_hours': None,
                'mttr_minutes': None,
            })

        # Operational status
        if alert_info.get('case_status') in ['Resolved', 'Closed']:
            alert_info['operational_status'] = 'Terminated'
        elif alert_info.get('case_id') and alert_info.get('case_status') in ['InProgress', 'Open']:
            alert_info['operational_status'] = 'In Progress'
        elif alert_info.get('case_id'):
            alert_info['operational_status'] = 'In Progress'
        else:
            alert_info['operational_status'] = 'Untreated'

        # Optional: detect false_positive / origin / detection_method from custom fields if present
        alert_info['false_positive'] = custom_fields.get('false_positive', None)
        alert_info['origin'] = custom_fields.get('origin', None)  # e.g. internal / external
        alert_info['detection_method'] = custom_fields.get('detection_method', None)  # e.g. automatic / manual

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

    # Avg takeover (KPI 1)
    if 'takeover_time_minutes' in df.columns and df['takeover_time_minutes'].notna().any():
        avg_takeover = df['takeover_time_minutes'].dropna().mean()
    else:
        avg_takeover = None

    # Add MTTD calculation (KPI 2)
    if 'mttd_minutes' in df.columns and df['mttd_minutes'].notna().any():
        avg_mttd = df['mttd_minutes'].dropna().mean()
        median_mttd = df['mttd_minutes'].dropna().median()
    else:
        avg_mttd = None
        median_mttd = None

    # Avg MTTR (KPI 3)
    if 'mttr_hours' in df.columns and df['mttr_hours'].notna().any():
        avg_mttr_hours = df['mttr_hours'].dropna().mean()
    else:
        avg_mttr_hours = None

    # Recompute MTTR explicitly from received -> terminated using the filtered df
    avg_mttr_calc = None
    median_mttr = None
    mttr_count = 0
    try:
        if 'case_closed_at' in df.columns and 'alert_received_time' in df.columns:
            mttr_series = (pd.to_datetime(df['case_closed_at']) - pd.to_datetime(df['alert_received_time'])).dt.total_seconds() / 3600
            mttr_valid = mttr_series.dropna()
            # If the current UI filter is Weekly, compute the weighted daily average:
            try:
                current_filter = st.session_state.get('filter_option', None)
            except Exception:
                current_filter = None

            if current_filter == 'Weekly' and not mttr_valid.empty and 'alert_created_at' in df.columns:
                # group by day (based on alert_created_at) to compute n_i and avg_i per day
                temp = pd.DataFrame({'alert_created_at': pd.to_datetime(df['alert_created_at']), 'mttr': mttr_series})
                temp = temp.dropna(subset=['mttr', 'alert_created_at'])
                if not temp.empty:
                    temp['date'] = temp['alert_created_at'].dt.date
                    daily = temp.groupby('date')['mttr'].agg(['count', 'mean']).reset_index()
                    # weighted average across days
                    numerator = (daily['count'] * daily['mean']).sum()
                    denominator = daily['count'].sum()
                    if denominator > 0:
                        avg_mttr_calc = numerator / denominator
                        median_mttr = mttr_valid.median()
                        mttr_count = int(denominator)
                    else:
                        avg_mttr_calc = None
                        median_mttr = None
                        mttr_count = 0
                else:
                    avg_mttr_calc = None
                    median_mttr = None
                    mttr_count = 0
            else:
                if len(mttr_valid) > 0:
                    avg_mttr_calc = mttr_valid.mean()
                    median_mttr = mttr_valid.median()
                    mttr_count = int(len(mttr_valid))
                else:
                    avg_mttr_calc = None
                    median_mttr = None
                    mttr_count = 0
    except Exception:
        avg_mttr_calc = None
        median_mttr = None
        mttr_count = 0

    # Keep existing avg response/resolution values if present
    avg_response = df['response_time_minutes'].mean() if 'response_time_minutes' in df.columns else None
    avg_resolution = df['resolution_time_hours'].mean() if 'resolution_time_hours' in df.columns else None

    # SLA compliance (example: takeover <= 30 minutes)
    if 'takeover_time_minutes' in df.columns and df['takeover_time_minutes'].notna().any():
        sla_takeover_pct = (df[df['takeover_time_minutes'] <= 30]['takeover_time_minutes'].count() / df['takeover_time_minutes'].dropna().count()) * 100
    else:
        sla_takeover_pct = None

    # Optional indicators
    # Robust false_positive detection
    false_positive_pct = None
    if 'false_positive' in df.columns:
        vals = df['false_positive'].dropna()
        if len(vals) > 0:
            def map_fp(x):
                s = str(x).strip().lower()
                if s in ['true', '1', 'yes', 'y', 'oui', 'vrai', 'fp', 'faux_positif', 'faux positif', 'false_positive', 'false-positive']:
                    return 1
                if s in ['false', '0', 'no', 'non', 'faux', 'not_fp']:
                    return 0
                # unknown -> treat as NaN
                return np.nan
            mapped = vals.map(map_fp)
            valid = mapped.dropna()
            if len(valid) > 0:
                false_positive_pct = valid.sum() / len(valid) * 100

    origin_stats = {}
    if 'origin' in df.columns:
        origin_stats = df['origin'].value_counts().to_dict()

    detection_stats = {}
    if 'detection_method' in df.columns:
        detection_stats = df['detection_method'].value_counts().to_dict()

    # First row of KPIs (reordered per user request)
    col1, col2, col3 = st.columns(3)

    # Total Alerts
    with col1:
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
            <div class="metric-value">{total_alerts}</div>
            <div class="metric-label">Total Alerts</div>
        </div>
        """, unsafe_allow_html=True)

    # Terminated
    with col2:
        terminated_text = f"{terminated}" if terminated is not None else "N/A"
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);">
            <div class="metric-value">{terminated_text}</div>
            <div class="metric-label">Terminated</div>
        </div>
        """, unsafe_allow_html=True)

    # In Progress
    with col3:
        in_progress_text = f"{in_progress}" if in_progress is not None else "N/A"
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
            <div class="metric-value">{in_progress_text}</div>
            <div class="metric-label">In Progress</div>
        </div>
        """, unsafe_allow_html=True)

    # Second row - Performance metrics (reordered)
    col5, col6, col7, col8, col9 = st.columns(5)  # Ajout d'une colonne

    # KPI 3 - MTTR

    with col5:
        takeover_text = f"{avg_takeover:.1f} min" if avg_takeover is not None else "N/A"
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
            <div class="metric-value">{takeover_text}</div>
            <div class="metric-label">KPI 1 - Temps de prise en charge</div>
        </div>
        """, unsafe_allow_html=True)

    with col6:
        mttd_text = f"{avg_mttd:.1f} min" if avg_mttd is not None else "N/A"
        mttd_sub = f"(median: {median_mttd:.1f} min)" if median_mttd is not None else ""
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 100%);">
            <div class="metric-value">{mttd_text}</div>
            <div class="metric-label">KPI 2 - Temps de Détection (MTTD)</div>
            <div class="metric-label" style="font-size:0.8rem; opacity:0.85;">{mttd_sub}</div>
        </div>
        """, unsafe_allow_html=True)

    with col7:
        mttr_text = f"{avg_mttr_calc:.1f} h" if avg_mttr_calc is not None else "N/A"
        mttr_sub = f"(median: {median_mttr:.1f} h, n={mttr_count})" if median_mttr is not None else ""
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
            <div class="metric-value">{mttr_text}</div>
            <div class="metric-label">KPI 3 - Temps de réponse (MTTR)</div>
            <div class="metric-label" style="font-size:0.8rem; opacity:0.85;">{mttr_sub}</div>
        </div>
        """, unsafe_allow_html=True)

    # Avg Response (created - received)
    with col8:
        response_text = f"{avg_response:.1f} min" if avg_response is not None else "N/A"
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #a78bfa 0%, #7c3aed 100%);">
            <div class="metric-value">{response_text}</div>
            <div class="metric-label">Avg Response (created - received)</div>
        </div>
        """, unsafe_allow_html=True)

    # Average Resolution Time

    # Third row - SLA, FP and Alerts/day
    col8, col9, col10 = st.columns(3)

    # SLA compliance: percent of alerts with response_time_minutes <= 30 among those with a response_time
    if 'response_time_minutes' in df.columns and df['response_time_minutes'].notna().any():
        sla_compliance = len(df[(df['response_time_minutes'] <= 30) & df['response_time_minutes'].notna()]) / len(df[df['response_time_minutes'].notna()]) * 100
    else:
        sla_compliance = None


    # SLA Compliance (displayed earlier as part of second row) and third row metrics
    with col8:
        sla_text = f"{sla_compliance:.1f}%" if sla_compliance is not None else "N/A"
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #f97316 0%, #fb7185 100%);">
            <div class="metric-value">{sla_text}</div>
            <div class="metric-label">SLA Prise en charge (&le; 30min)</div>
        </div>
        """, unsafe_allow_html=True)

    with col9:
        sla_text2 = f"{sla_compliance:.1f}%" if sla_compliance is not None else "N/A"
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #f97316 0%, #fb7185 100%);">
            <div class="metric-value">{sla_text2}</div>
            <div class="metric-label">SLA Compliance (&le; 30 min)</div>
        </div>
        """, unsafe_allow_html=True)

    # Calcul amélioré des faux positifs
    terminated_cases = df[df['operational_status'] == 'Terminated']

    # Safe check for resolutionStatus column
    has_resolution_status = 'resolutionStatus' in terminated_cases.columns

    false_positive_cases = terminated_cases[
        (terminated_cases['false_positive'] == True) |
        (has_resolution_status & (terminated_cases['resolutionStatus'].str.lower() == 'falsepositive'))
    ]

    if len(terminated_cases) > 0:
        false_positive_pct = (len(false_positive_cases) / len(terminated_cases)) * 100
    else:
        false_positive_pct = 0

    with col10:
        fp_text = f"{false_positive_pct:.1f}%" if false_positive_pct is not None else "N/A"
        details = f"({len(false_positive_cases)} sur {len(terminated_cases)} cas terminés)"
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #f0abfc 0%, #f97316 100%);">
            <div class="metric-value">{fp_text}</div>
            <div class="metric-label">% Faux Positifs</div>
            <div class="metric-label" style="font-size:0.8rem;">{details}</div>
        </div>
        """, unsafe_allow_html=True)

    # Calcul du taux interne vs externe
    type_counts = df['type'].value_counts()
    total_incidents = len(df)
    internal_count = type_counts.get('internal', 0)
    external_count = type_counts.get('external', 0)

    if total_incidents > 0:
        internal_rate = (internal_count / total_incidents) * 100
        external_rate = (external_count / total_incidents) * 100
    else:
        internal_rate = 0
        external_rate = 0

    # Calcul du taux automatique vs manuel
    detection_counts = df['mode_detection'].value_counts()
    # Modifier cette partie pour prendre en compte toutes les variations possibles
    auto_count = sum(detection_counts.get(x, 0) for x in ['automatique', 'automatic', 'Automatique', 'Automatic'])
    manual_count = sum(detection_counts.get(x, 0) for x in ['manuel', 'manual', 'Manuel', 'Manual'])
    total_detections = auto_count + manual_count

    

    if total_detections > 0:
        auto_rate = (auto_count / total_detections) * 100
        manual_rate = (manual_count / total_detections) * 100
    else:
        auto_rate = 0
        manual_rate = 0

    # Après vos colonnes existantes, ajoutez:
    col11, col12 = st.columns(2)

    # Taux interne vs externe
    with col11:
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%);">
            <div class="metric-value">{internal_rate:.1f}% / {external_rate:.1f}%</div>
            <div class="metric-label">Taux Interne vs Externe</div>
            <div class="metric-label" style="font-size:0.8rem;">({internal_count} int. / {external_count} ext.)</div>
        </div>
        """, unsafe_allow_html=True)

    # Taux automatique vs manuel
    with col12:
        st.markdown(f"""
        <div class="metric-container" style="background: linear-gradient(135deg, #8b5cf6 0%, #d946ef 100%);">
            <div class="metric-value">{auto_rate:.1f}% / {manual_rate:.1f}%</div>
            <div class="metric-label">Taux Auto vs Manuel</div>
            <div class="metric-label" style="font-size:0.8rem;">({auto_count} auto. / {manual_count} man.)</div>
        </div>
        """, unsafe_allow_html=True)

    # Visualisation des distributions
    col13, col14 = st.columns(2)

    with col13:
        # Graphique pour Interne vs Externe
        fig_type = go.Figure(data=[go.Pie(
            labels=['Interne', 'Externe'],
            values=[internal_count, external_count],
            hole=.5,
            marker_colors=['#3b82f6', '#06b6d4']
        )])
        fig_type.update_layout(
            title_text="Distribution Interne/Externe",
            height=300,
            showlegend=True
        )
        st.plotly_chart(fig_type, use_container_width=True)

    with col14:
        # Graphique pour Auto vs Manuel
        fig_detection = go.Figure(data=[go.Pie(
            labels=['Automatique', 'Manuel'],
            values=[auto_count, manual_count],
            hole=.5,
            marker_colors=['#8b5cf6', '#d946ef']
        )])
        fig_detection.update_layout(
            title_text="Distribution Auto/Manuel",
            height=300,
            showlegend=True
        )
        st.plotly_chart(fig_detection, use_container_width=True)

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
        height=300,
        margin=dict(t=80, b=20, l=20, r=20)
    )

    st.plotly_chart(fig, use_container_width=True)

# Note: Response time analysis chart removed per request. Use assignment performance dashboard for analyst reactivity.

def create_assignment_performance_dashboard(df):
    """Assignment performance dashboard"""
    assigned_data = df[df['assigned_to'] != 'Unassigned'].copy()

    if assigned_data.empty:
        st.info("No assignment data available")
        return

    # Analysis by assignee
    # Per-assignee stats: count, terminated count, avg resolution, avg response, SLA compliance
    def sla_comp(series):
        valid = series.dropna()
        if len(valid) == 0:
            return np.nan
        return (valid <= 30).sum() / len(valid) * 100

    # Build per-assignee statistics including SLA compliance
    assignment_stats = assigned_data.groupby('assigned_to').apply(
        lambda g: pd.Series({
            'Total_Cases': g['alert_id'].count(),
            'Cases_Terminated': (g['operational_status'] == 'Terminated').sum(),
            'Avg_Resolution_Time': g['resolution_time_hours'].mean(),
            'Avg_Response_Time': g['response_time_minutes'].mean(),
            'SLA_Compliance': sla_comp(g['response_time_minutes'])
        })
    ).reset_index()

    assignment_stats.columns = ['Assignee', 'Total_Cases', 'Cases_Terminated', 'Avg_Resolution_Time', 'Avg_Response_Time', 'SLA_Compliance']

    # Ensure numeric types and fill NaN values
    assignment_stats['Avg_Resolution_Time'] = pd.to_numeric(assignment_stats['Avg_Resolution_Time'], errors='coerce').fillna(0)
    assignment_stats['Avg_Response_Time'] = pd.to_numeric(assignment_stats['Avg_Response_Time'], errors='coerce').fillna(0)
    assignment_stats['SLA_Compliance'] = pd.to_numeric(assignment_stats['SLA_Compliance'], errors='coerce')

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
        height=500,
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
    display_stats['SLA_Compliance'] = display_stats['SLA_Compliance'].round(1).fillna(0)
    display_stats['Completion_Rate'] = (display_stats['Cases_Terminated'] / display_stats['Total_Cases'] * 100).round(1)

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
            ),
            "SLA_Compliance": st.column_config.NumberColumn(
                "SLA Compliance (%)",
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

    # Ensure datetime
    timeline_data['date'] = pd.to_datetime(timeline_data['alert_created_at']).dt.date
    timeline_data['hour'] = pd.to_datetime(timeline_data['alert_created_at']).dt.hour

    # Daily stats
    daily_stats = timeline_data.groupby('date').agg({
        'alert_id': 'count',
        'response_time_minutes': 'mean',
        'operational_status': lambda x: (x == 'Terminated').sum(),
        'resolution_time_hours': 'mean'
    }).reset_index()
    daily_stats.columns = ['Date', 'Nb_Alerts', 'Avg_Response', 'Nb_Terminated', 'Avg_Resolution']

    # Top categories and sources (KPI 5)
    top_types = timeline_data['type'].value_counts().nlargest(10).reset_index()
    top_types.columns = ['Type', 'Count']
    top_sources = timeline_data['source'].value_counts().nlargest(10).reset_index()
    top_sources.columns = ['Source', 'Count']

    # Combined temporal + category display
    fig = make_subplots(
        rows=3, cols=2,
        subplot_titles=('Alert Volume by Day', 'Average Response Time',
                       'Hourly Distribution', 'Resolution Trend', 'Top Categories', 'Top Sources'),
        specs=[[{"secondary_y": False}, {"secondary_y": False}],
               [{"secondary_y": False}, {"secondary_y": False}],
               [{"type": "bar"}, {"type": "bar"}]]
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

    # Top categories
    fig.add_trace(
        go.Bar(x=top_types['Type'], y=top_types['Count'], marker_color='#f59e0b', name='Categories'),
        row=3, col=1
    )

    # Top sources
    fig.add_trace(
        go.Bar(x=top_sources['Source'], y=top_sources['Count'], marker_color='#ef4444', name='Sources'),
        row=3, col=2
    )

    fig.update_layout(
        height=900,
        title_text="Complete Temporal & Category Analysis",
        title_x=0.5,
        showlegend=False
    )

    st.plotly_chart(fig, use_container_width=True)

    # Additional tables / breakdowns for KPI 5 details
    st.markdown('<div class="section-header">KPI 5 — Tendances & Corrélations</div>', unsafe_allow_html=True)
    colA, colB = st.columns(2)

    with colA:
        st.subheader("Top Categories")
        st.dataframe(top_types, use_container_width=True, hide_index=True)

    with colB:
        st.subheader("Top Sources")
        st.dataframe(top_sources, use_container_width=True, hide_index=True)

    # Optional: show detection / origin distributions
    if 'detection_method' in timeline_data.columns:
        st.subheader("Detection Method Distribution")
        st.bar_chart(timeline_data['detection_method'].value_counts())

    if 'origin' in timeline_data.columns:
        st.subheader("Origin (internal vs external)")
        st.bar_chart(timeline_data['origin'].value_counts())

def priority_to_numeric(priority):
    """Convert priority string (P1-P4) to numeric value (4-1)"""
    priority_map = {
        'P1': 4,  # P1 (Critique) -> 4
        'P2': 3,  # P2 (Haute) -> 3
        'P3': 2,  # P3 (Moyenne) -> 2
        'P4': 1   # P4 (Basse) -> 1
    }
    return priority_map.get(priority, 0)  # Return 0 for invalid priorities

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
        st.markdown(f"### 👋 *{auth_info.get('user_name', auth_info.get('username', 'User'))}*")
        st.markdown("---")

        st.header("Configuration")

        if st.button("Refresh Data", type="primary", use_container_width=True):
            st.cache_data.clear()
            st.session_state.df = None
            st.rerun()

        st.subheader("Date Filters")

        # Daily filter
        selected_date = st.date_input("Select a date", value=datetime.now().date())
        st.session_state.selected_date = selected_date

        # Weekly, Monthly, Quarterly filters
        filter_option = st.selectbox("Select Filter Type", ["Daily", "Weekly", "Monthly", "Quarterly"])
        st.session_state.filter_option = filter_option

        st.subheader("Operational Status Filter")
        status_filter = st.multiselect(
            "Operational Status",
            ['Untreated', 'In Progress', 'Terminated'],
            default=st.session_state.filters['status_filter'],
            key="status_filter"
        )
        st.session_state.filters['status_filter'] = status_filter

        # Timezone selection for display (user can override detected timezone)
        tz_options = ['System Local', 'Africa/Casablanca', 'Europe/Berlin', 'UTC']
        default_tz = st.session_state.get('display_tz', 'System Local')
        if default_tz not in tz_options:
            default_tz = 'System Local'
        selected_tz = st.selectbox("Display Timezone", tz_options, index=tz_options.index(default_tz), key='display_tz')

        # Option: afficher les timestamps bruts (pas de conversion de fuseau)
        show_raw = st.checkbox("Afficher timestamps bruts (pas de conversion de fuseau)", value=False, key='show_raw_timestamps')

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
            st.success(f"✅ Loaded *{len(df):,} alerts*")
    else:
        df = st.session_state.df
        st.info(f"📊 Using cached data: *{len(df):,} alerts*")

    # Filter data based on selected date and filter option
    if not df.empty:
        # Ensure consistent datetime types for comparison
        df['alert_created_at'] = pd.to_datetime(df['alert_created_at'])

        if st.session_state.filter_option == "Daily":
            df = df[df['alert_created_at'].dt.date == st.session_state.selected_date]
        elif st.session_state.filter_option == "Weekly":
            start_of_week = pd.Timestamp(st.session_state.selected_date - pd.Timedelta(days=st.session_state.selected_date.weekday()))
            end_of_week = pd.Timestamp(start_of_week + pd.Timedelta(days=6))
            end_of_week = end_of_week + pd.Timedelta(hours=23, minutes=59, seconds=59)
            df = df[(df['alert_created_at'] >= start_of_week) & (df['alert_created_at'] <= end_of_week)]
        elif st.session_state.filter_option == "Monthly":
            df = df[df['alert_created_at'].dt.month == st.session_state.selected_date.month]
            df = df[df['alert_created_at'].dt.year == st.session_state.selected_date.year]
        elif st.session_state.filter_option == "Quarterly":
            quarter = (st.session_state.selected_date.month - 1) // 3 + 1
            df = df[(df['alert_created_at'].dt.month - 1) // 3 + 1 == quarter]
            df = df[df['alert_created_at'].dt.year == st.session_state.selected_date.year]

        # Filter by operational status
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
        create_assignment_performance_dashboard(df)

    st.divider()

    # Removed separate Performance Analysis and Temporal Analysis sections per request

    st.divider()

    # Detailed table
    st.markdown('<div class="section-header">Detailed Data</div>', unsafe_allow_html=True)

    if not df.empty:
        # Colonnes à afficher (avec alert_received_time et case_created_at)
        display_columns = [
            'alert_title',
            'sourceRef',
            'severity',           # Ajout de la sévérité
            'type',              # Ajout du type
            'mode_detection',    # Ajout du mode de détection
            'alert_generated_time',    # Temps initial de l'incident
            'alert_received_time',     # Temps de détection par ELK
            'processing_start_time',   # Début du traitement
            'alert_created_at',        # Création dans TheHive
            'case_created_at',         # Ouverture du case
            'case_closed_at',         # Clôture du case
            'mttd_minutes',           # Métrique MTTD
            'response_time_minutes',  # Temps de réponse
            'resolution_time_hours',  # Temps de résolution
            'assigned_to',           # Assignation
            'operational_status'     # État actuel
        ]

        available_columns = [col for col in display_columns if col in df.columns]

        # Configuration des colonnes avec descriptions
        column_config = {
            "alert_title": st.column_config.TextColumn(
                "Titre de l'alerte",
                help="Le titre descriptif de l'alerte"
            ),
            "sourceRef": st.column_config.TextColumn(
                "Référence",
                help="Identifiant unique de référence de l'alerte"
            ),
            "severity": st.column_config.TextColumn(
                "Priorité",
                help="Niveau de priorité de l'alerte (P1: Critique, P2: Haute, P3: Moyenne, P4: Basse)",
            ),
            "type": st.column_config.TextColumn(
                "Type",
                help="Type de l'alerte (ex: externe, interne)"
            ),
            "mode_detection": st.column_config.TextColumn(
                "Mode Détection",
                help="Mode de détection de l'alerte"
            ),
            "alert_generated_time": st.column_config.TextColumn(
                "Temps de l'incident",
                help="Le temps réel où l'incident s'est produit dans le système source"
            ),
            "alert_received_time": st.column_config.TextColumn(
                "Temps de détection",
                help="Le moment où l'incident est détecté par ELK"
            ),
            "processing_start_time": st.column_config.TextColumn(
                "Début traitement",
                help="Le temps de début de traitement de l'incident par l'équipe"
            ),
            "alert_created_at": st.column_config.TextColumn(
                "Création alerte",
                help="Le temps de création de l'alerte dans TheHive et notification de l'équipe Marjane"
            ),
            "case_created_at": st.column_config.TextColumn(
                "Ouverture case",
                help="La date d'ouverture du dossier d'investigation (case)"
            ),
            "case_closed_at": st.column_config.TextColumn(
                "Clôture case",
                help="La date de clôture définitive du dossier"
            ),
            "mttd_minutes": st.column_config.NumberColumn(
                "MTTD (min)",
                help="Mean Time To Detect: Temps entre la génération de l'incident et sa détection",
                format="%.1f"
            ),
            "response_time_minutes": st.column_config.NumberColumn(
                "Temps réponse (min)",
                help="Temps entre la détection et le début du traitement",
                format="%.1f"
            ),
            "resolution_time_hours": st.column_config.NumberColumn(
                "Temps résolution (h)",
                help="Temps total entre l'ouverture et la clôture du case",
                format="%.1f"
            ),
            "assigned_to": st.column_config.TextColumn(
                "Assigné à",
                help="L'analyste responsable du traitement"
            ),
            "operational_status": st.column_config.SelectboxColumn(
                "Statut",
                options=['Untreated', 'In Progress', 'Terminated'],
                help="État opérationnel actuel de l'alerte: Non traité, En cours, ou Terminé"
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

        # Handle timestamp display
        display_df = df[available_columns].copy()
        use_raw = st.session_state.get('show_raw_timestamps', False)

        # Format timestamps as they appear in TheHive UI
        for col in ['alert_created_at', 'alert_received_time', 'case_created_at', 'case_closed_at', 'processing_start_time']:
            if col in display_df.columns:
                try:
                    # Keep the timestamp as is since we already adjusted it in process_operational_data
                    display_df[col] = pd.to_datetime(display_df[col], errors='coerce').dt.strftime('%d/%m/%Y %H:%M')
                except Exception:
                    # Fallback: simple formatting if something fails
                    display_df[col] = pd.to_datetime(display_df[col], errors='coerce').dt.strftime('%d/%m/%Y %H:%M')

        styled_df = display_df.head(100).style.applymap(style_status, subset=['operational_status'])
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

            # Nouveau calcul de la moyenne de sévérité
            if not df.empty and 'severity' in df.columns:
                numeric_severities = df['severity'].apply(priority_to_numeric)
                severity_avg = numeric_severities[numeric_severities > 0].mean() if len(numeric_severities[numeric_severities > 0]) > 0 else 0
                # Convertir la moyenne numérique en format P
                severity_display = f"P{5-round(severity_avg)}" if severity_avg > 0 else "N/A"
            else:
                severity_display = "N/A"

            st.markdown(f"""
            <div class="kpi-card">
                <h4 style="margin-top:0; color:#374151;">Sources & Severity</h4>
                <p><strong>Unique Sources:</strong> {total_sources}</p>
                <p><strong>Main Source:</strong> {most_frequent_source}</p>
                <p><strong>Average Severity:</strong> {severity_display}</p>
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

    # Display timezone for footer
    sel_tz_name = st.session_state.get('display_tz', 'System Local')
    if sel_tz_name == 'System Local':
        footer_tz = _GET_LOCAL_TZ()
    elif sel_tz_name == 'UTC':
        footer_tz = 'UTC'
    else:
        footer_tz = sel_tz_name

    with info_col1:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: #f8fafc; border-radius: 8px;">
            <h5 style="margin:0; color:#64748b;">Last Update</h5>
            <p style="margin:0; color:#374151;">{datetime.now().astimezone(footer_tz if not isinstance(footer_tz, str) else ZoneInfo(footer_tz)).strftime('%d/%m/%Y at %H:%M:%S %Z')}</p>
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
            <p style="margin:0; color:#374151; font-size:0.85rem;">Timezone: {footer_tz}</p>
        </div>
        """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
