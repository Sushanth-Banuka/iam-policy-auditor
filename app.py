import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import os
import json

from auditor.mock_data import MockIAMData
from auditor.risk_engine import RiskEngine
from reports.db import AuditDB
from reports.report_gen import generate_pdf, generate_csv

try:
    from auditor.rbac_scanner import RBACScanner, AZURE_AVAILABLE
except ImportError:
    AZURE_AVAILABLE = False
    RBACScanner = None

st.set_page_config(page_title="IAM Policy Auditor", page_icon="🔐", layout="wide")

st.markdown("""
<style>
/* Glassmorphism Cyber Theme */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');

[data-testid="stAppViewContainer"] { 
    background: radial-gradient(circle at 15% 50%, #141727, #0b0c10); 
    color: #e2e8f0; 
    font-family: 'Inter', sans-serif;
}
[data-testid="stSidebar"] { 
    background-color: rgba(11, 12, 16, 0.65); 
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border-right: 1px solid rgba(255, 255, 255, 0.05); 
}
[data-testid="stHeader"] { background-color: rgba(11, 12, 16, 0); }

/* Glassmorphism Metrics */
.stMetric, div[data-testid="metric-container"] {
    background: rgba(30, 33, 43, 0.4);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px; 
    padding: 15px;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.stMetric:hover, div[data-testid="metric-container"]:hover {
    transform: translateY(-2px);
    box-shadow: 0 12px 40px 0 rgba(0, 255, 204, 0.1);
    border: 1px solid rgba(0, 255, 204, 0.3);
}

hr { border-top: 1px solid rgba(255, 255, 255, 0.1); }

/* Finding Cards with Neon Glow accents */
.finding-card {
    background: rgba(20, 25, 35, 0.6); 
    backdrop-filter: blur(8px);
    border-radius: 12px; 
    padding: 20px; 
    margin-bottom: 18px; 
    box-shadow: 0 4px 15px rgba(0,0,0,0.5);
    border: 1px solid rgba(255, 255, 255, 0.05);
    transition: all 0.3s ease;
}
.finding-card:hover {
    background: rgba(30, 35, 45, 0.8);
    box-shadow: 0 8px 25px rgba(0,0,0,0.5);
}

.mitre-badge {
    background: linear-gradient(135deg, #8A2387, #E94057, #F27121);
    color: white; 
    padding: 4px 10px; 
    border-radius: 20px;
    font-size: 0.75em; 
    font-weight: 800; 
    display: inline-block; 
    margin: 8px 0;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    box-shadow: 0 2px 10px rgba(233, 64, 87, 0.4);
}

/* Gradient Severity Badges */
.sev-badge { 
    padding: 4px 10px; 
    border-radius: 6px; 
    font-size: 0.8em; 
    font-weight: 800; 
    display: inline-block; 
    margin-right: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.sev-Critical { background: linear-gradient(90deg, #ff0844 0%, #ffb199 100%); color: white; box-shadow: 0 0 10px rgba(255, 8, 68, 0.4); }
.sev-High { background: linear-gradient(90deg, #f83600 0%, #f9d423 100%); color: white; box-shadow: 0 0 10px rgba(248, 54, 0, 0.4); }
.sev-Medium { background: linear-gradient(90deg, #f6d365 0%, #fda085 100%); color: #1a1a1a; box-shadow: 0 0 10px rgba(246, 211, 101, 0.4); }
.sev-Low { background: linear-gradient(90deg, #0ba360 0%, #3cba92 100%); color: white; box-shadow: 0 0 10px rgba(11, 163, 96, 0.4); }

a { color: #00f2fe; text-decoration: none; transition: color 0.2s; }
a:hover { color: #fe0979; }

/* Custom Button Styling */
.stButton > button {
    background: linear-gradient(45deg, #00f2fe, #4facfe);
    color: #0b0c10;
    font-weight: bold;
    border: none;
    border-radius: 8px;
    transition: all 0.3s ease;
}
.stButton > button:hover {
    transform: scale(1.02);
    box-shadow: 0 0 20px rgba(0, 242, 254, 0.5);
    color: #fff;
}
</style>
""", unsafe_allow_html=True)

# Initialize DB
db = AuditDB()

@st.cache_data(ttl=30)
def get_history_cached():
    return db.get_history()

if "scan_results" not in st.session_state:
    st.session_state.scan_results = None

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# --- LOGIN SCREEN ---
if not st.session_state.authenticated:
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    login_col1, login_col2, login_col3 = st.columns([1, 1.5, 1])
    
    with login_col2:
        st.markdown("""
        <div style='text-align: center; margin-bottom: 30px;'>
            <h1 style='font-size: 60px; margin-bottom: 0;'>🔐</h1>
            <h2 style='background: linear-gradient(45deg, #00f2fe, #4facfe); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>IAM Policy Auditor</h2>
            <p style='color: #8b949e;'>Secure Identity & Access Management Platform</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            st.markdown("### Authentication Required")
            username = st.text_input("Username", placeholder="Enter your registered email")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submit = st.form_submit_button("Secure Login", use_container_width=True)
            
            if submit:
                if username == "admin" and password == "admin":
                    st.session_state.authenticated = True
                    st.rerun()
                else:
                    st.error("Invalid credentials. Please try again.")
    st.stop()
# --- END LOGIN SCREEN ---

# Sidebar
with st.sidebar:
    st.title("⚙️ Configuration")
    use_real_azure = st.toggle("Connect Real Azure Account", value=False)
    
    tenant_id, client_id, client_secret, sub_id = "", "", "", ""
    if use_real_azure:
        st.info("🌐 Live Azure Mode")
        tenant_id = st.text_input("Tenant ID", type="password")
        client_id = st.text_input("Client ID", type="password")
        client_secret = st.text_input("Client Secret", type="password")
        sub_id = st.text_input("Subscription ID", type="password")
        if not AZURE_AVAILABLE:
            st.warning("Azure SDK not fully available. Will fallback to mock.")
    else:
        st.info("🧪 Demo Mode — Simulated Azure IAM data")
        
    st.subheader("Scan Scope")
    inc_users = st.checkbox("Users & Groups", value=True)
    inc_sps = st.checkbox("Service Principals", value=True)
    inc_managed = st.checkbox("Managed Identities", value=True)
    inc_guests = st.checkbox("Guest Accounts", value=True)
    
    if st.button("▶ Run Audit", use_container_width=True, type="primary"):
        with st.spinner("🔍 Scanning IAM policies..."):
            try:
                if use_real_azure and AZURE_AVAILABLE:
                    scanner = RBACScanner(tenant_id, client_id, client_secret, sub_id)
                    assignments = scanner.scan()
                else:
                    assignments = MockIAMData.generate(inc_users, inc_sps, inc_managed, inc_guests)
                    
                results = RiskEngine().analyze(assignments)
                db.save_audit(results)
                st.session_state.scan_results = results
                st.toast("✅ Scan Completed Successfully!")
            except Exception as e:
                st.error(f"Scan failed: {str(e)}")
            
    st.divider()
    st.subheader("Audit History")
    history = get_history_cached()
    if history:
        for entry in history[:5]:
            # Convert timestamp to readable format
            try:
                dt = datetime.fromisoformat(entry['timestamp'])
                dt_str = dt.strftime("%Y-%m-%d %H:%M")
            except:
                dt_str = entry['timestamp']
            st.caption(f"📅 {dt_str} | 🔴 {entry['critical']} | 🟠 {entry['high']}")
    else:
        st.caption("No previous audits.")
        
    st.divider()
    st.markdown("<small>Built by [Sushanth Banuka](https://github.com/Sushanth-Banuka)</small>", unsafe_allow_html=True)

# Main Area
st.title("IAM Policy Auditor 🔐")
st.markdown("<h4 style='color: #8b949e; font-weight: normal; margin-top: -10px;'>Azure Identity & Access Management Security Auditing Tool</h4>", unsafe_allow_html=True)

if not st.session_state.scan_results:
    st.markdown("<br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.markdown("<h1 style='text-align: center; font-size: 80px;'>🔐</h1>", unsafe_allow_html=True)
        st.markdown("<h3 style='text-align: center;'>Welcome to IAM Policy Auditor</h3>", unsafe_allow_html=True)
        st.info("👈 **Configure your scan settings in the sidebar and click 'Run Audit' to begin.**\n\n- Connect to real Azure or use Demo Mode to simulate findings.\n- Detects 7 critical mitigation issues mapping directly to MITRE ATT&CK.\n- Auto-generates remediation CLI scripts for instant fixes.")
else:
    results = st.session_state.scan_results
    summary = results["summary"]
    findings = results["findings"]
    principals = results["principals"]
    
    # Metrics Row
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    
    grade_letter, grade_color, grade_label = summary["score_grade"]
    c1.metric("Security Score", f"{summary['security_score']}/100")
    c1.markdown(f"<div style='margin-top: -15px; font-weight: bold; color: {grade_color};'>{grade_letter} - {grade_label}</div>", unsafe_allow_html=True)
    
    c2.metric("Critical", summary["critical"])
    c3.metric("High", summary["high"])
    c4.metric("Medium", summary["medium"])
    c5.metric("Low", summary["low"])
    c6.metric("Total Findings", summary["total"])
    
    st.markdown("<hr style='margin-top: 10px; margin-bottom: 20px;'>", unsafe_allow_html=True)
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🚨 Findings", "🔧 Remediation", "👤 Principals", "📊 Analytics", "📤 Export"])
    
    with tab1:
        colA, colB = st.columns(2)
        with colA:
            sev_filter = st.multiselect("Filter by Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
        with colB:
            unique_types = list(set([f["type"] for f in findings]))
            type_filter = st.multiselect("Filter by Finding Type", unique_types, default=unique_types)
            
        filtered_f = [f for f in findings if f["severity"] in sev_filter and f["type"] in type_filter]
        
        # Sort by severity
        sev_w = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        filtered_f = sorted(filtered_f, key=lambda x: sev_w.get(x["severity"], 0), reverse=True)
        
        if not filtered_f:
            st.success("No findings match the current filters.")
            
        for f in filtered_f:
            border_color = {"Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107", "Low": "#28a745"}.get(f["severity"], "#30363D")
            st.markdown(f"""
            <div class='finding-card' style='border-left: 4px solid {border_color};'>
                <div style='margin-bottom: 10px;'>
                    <span class='sev-badge sev-{f["severity"]}'>{f["severity"]}</span>
                    <strong>{f["type"]}</strong>
                </div>
                <div class='mitre-badge'>🛡️ {f["mitre_id"]} ({f["mitre_tactic"]}): {f["mitre_name"]}</div>
                <p><strong>Principal:</strong> {f["principal"]}<br>
                <strong>Role:</strong> {f["role"]}<br>
                <strong>Scope:</strong> {f["scope"]}</p>
                <p><em>{f["description"]}</em></p>
                <p style='color: #00FFCC;'>💡 <strong>Recommendation:</strong> {f["recommendation"]}</p>
            </div>
            """, unsafe_allow_html=True)
            
    with tab2:
        st.markdown("### Auto-Generated Remediation Commands")
        # Critical and High only
        rem_findings = [f for f in findings if f["severity"] in ["Critical", "High"]]
        rem_findings = sorted(rem_findings, key=lambda x: sev_w.get(x["severity"], 0), reverse=True)
        
        if not rem_findings:
            st.success("No Critical or High findings require immediate remediation!")
            
        for f in rem_findings:
            with st.expander(f"[{f['severity']}] {f['type']} — {f['principal']}"):
                st.markdown(f"<div class='mitre-badge'>🛡️ {f['mitre_id']}</div> {f['description']}", unsafe_allow_html=True)
                st.code(f["remediation_cli"], language="bash")
                
    with tab3:
        unique_p_types = list(set([p["type"] for p in principals]))
        p_type_filter = st.selectbox("Filter by Principal Type", ["All"] + unique_p_types)
        
        df_p = pd.DataFrame(principals)
        if p_type_filter != "All":
            df_p = df_p[df_p["type"] == p_type_filter]
            
        def color_risk(val):
            color = {"Critical": "red", "High": "orange", "Medium": "yellow", "Low": "green"}.get(val, "white")
            return f'color: {color}'
            
        if not df_p.empty:
            styled_df = df_p.style.map(color_risk, subset=['risk_level'])
            st.dataframe(styled_df, use_container_width=True)
        else:
            st.info("No principals found.")
            
    with tab4:
        if findings:
            df_f = pd.DataFrame(findings)
            df_p_all = pd.DataFrame(principals)
            
            c1, c2 = st.columns(2)
            
            # 1. Findings by Severity
            fig1 = px.histogram(df_f, x="severity", color="severity",
                               category_orders={"severity": ["Critical", "High", "Medium", "Low"]},
                               color_discrete_map={"Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107", "Low": "#28a745"},
                               title="Findings by Severity")
            fig1.update_layout(template="plotly_dark", plot_bgcolor="#161B22", paper_bgcolor="#161B22")
            c1.plotly_chart(fig1, use_container_width=True)
            
            # 2. Findings by MITRE Tactic
            fig2 = px.pie(df_f, names="mitre_tactic", title="Findings by MITRE ATT&CK Tactic", hole=0.3)
            fig2.update_layout(template="plotly_dark", plot_bgcolor="#161B22", paper_bgcolor="#161B22")
            c2.plotly_chart(fig2, use_container_width=True)
            
            c3, c4 = st.columns(2)
            
            # 3. Principals by Type
            if not df_p_all.empty:
                fig3 = px.histogram(df_p_all, x="type", title="Principals by Entity Type", color="type")
                fig3.update_layout(template="plotly_dark", plot_bgcolor="#161B22", paper_bgcolor="#161B22")
                c3.plotly_chart(fig3, use_container_width=True)
            else:
                c3.info("No principal data for charting.")
            
            # 4. MITRE ATT&CK Technique Coverage
            fig4 = px.histogram(df_f, x="mitre_id", title="MITRE ATT&CK Technique Coverage", color="mitre_id")
            fig4.update_layout(template="plotly_dark", plot_bgcolor="#161B22", paper_bgcolor="#161B22")
            c4.plotly_chart(fig4, use_container_width=True)
        else:
            st.info("No findings available to generate analytics.")

    with tab5:
        st.markdown("### Export Reports")
        ex1, ex2, ex3 = st.columns(3)
        
        if ex1.button("📄 Generate PDF Report", use_container_width=True):
            pdf_bytes = generate_pdf(results, results["scanned_at"])
            ex1.download_button(
                label="⬇ Download PDF",
                data=pdf_bytes,
                file_name=f"IAM_Audit_Report_{results['scanned_at'].split('T')[0]}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        
        csv_data = generate_csv(findings)
        ex2.download_button(
            label="📊 Download CSV Findings",
            data=csv_data,
            file_name=f"IAM_Findings_{results['scanned_at'].split('T')[0]}.csv",
            mime="text/csv",
            use_container_width=True
        )
        
        json_data = json.dumps(results, indent=2)
        ex3.download_button(
            label="🧩 Download Full JSON",
            data=json_data,
            file_name=f"IAM_Full_Results_{results['scanned_at'].split('T')[0]}.json",
            mime="application/json",
            use_container_width=True
        )
        
        st.markdown("<br>", unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(findings), use_container_width=True)
