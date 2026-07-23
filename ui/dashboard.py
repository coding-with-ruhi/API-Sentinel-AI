import os
import sys

# ---------------------------------------------------------
# Add Project Root to Python Path
# ---------------------------------------------------------

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------
# Imports
# ---------------------------------------------------------

import streamlit as st
import json
import pandas as pd

from scanner.pipeline import APISentinelPipeline

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------

st.set_page_config(
    page_title="API Sentinel AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------
# Custom Theme
# ---------------------------------------------------------

st.markdown(
    """
    <style>

    .stApp{
        background-color:#0b1020;
        color:white;
    }

    .main-title{
        font-size:48px;
        font-weight:800;
        color:#b388ff;
        text-align:center;
    }

    .subtitle{
        font-size:18px;
        text-align:center;
        color:#c7c7c7;
        margin-bottom:30px;
    }

    .card{
        background:#171d33;
        border-radius:15px;
        padding:20px;
        margin-top:15px;
        border:1px solid #6f42c1;
    }

    .section-title{
        font-size:24px;
        font-weight:bold;
        color:#b388ff;
        margin-top:20px;
    }

    div.stButton > button{
        background:#7c3aed;
        color:white;
        font-weight:bold;
        border:none;
        border-radius:12px;
        padding:12px 30px;
    }

    div.stButton > button:hover{
        background:#9d5cff;
        color:white;
    }

    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# Sidebar
# ---------------------------------------------------------

with st.sidebar:

    st.title("🛡️ API Sentinel AI")

    st.markdown("---")

    st.markdown(
        """
        ### Scan Workflow

        ✅ Discovery Engine

        ✅ Intelligence Engine

        ✅ LLM Test Planner

        ✅ Security Executor

        ✅ Validation Engine

        ✅ Risk Engine

        ✅ AI Analyst

        ✅ Report Generator
        """
    )

    st.markdown("---")

    st.success("System Status: Ready")

# ---------------------------------------------------------
# Header
# ---------------------------------------------------------

st.markdown(
    """
    <div class="main-title">
        API Sentinel AI
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="subtitle">
        AI-Powered API Security Assessment Platform
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# Scan Configuration
# ---------------------------------------------------------

st.markdown(
    '<div class="section-title">Target OpenAPI Specification</div>',
    unsafe_allow_html=True,
)

openapi_url = st.text_input(
    "",
    value="http://127.0.0.1:5000/openapi.json",
)

scan_button = st.button(
    "🚀 Start Security Scan",
    use_container_width=True,
)

# ---------------------------------------------------------
# Session State
# ---------------------------------------------------------

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None

# ---------------------------------------------------------
# Run Scan
# ---------------------------------------------------------

if scan_button:

    pipeline = APISentinelPipeline()

    progress = st.progress(0)

    status = st.empty()

    try:

        status.info("🚀 Initializing API Sentinel AI...")

        progress.progress(10)

        status.info("🔍 Discovering API Endpoints...")

        progress.progress(25)

        status.info("🧠 Running Intelligence Engine...")

        progress.progress(40)

        status.info("🤖 Generating Security Test Plans...")

        progress.progress(55)

        status.info("⚡ Executing Security Tests...")

        progress.progress(70)

        status.info("🛡 Validating Findings...")

        progress.progress(80)

        status.info("📊 Calculating Risk Scores...")

        progress.progress(90)

        status.info("📝 Generating Professional Report...")

        result = pipeline.scan_safe(
            openapi_url
        )

        progress.progress(100)

        if result is None:

            st.error(
                "Pipeline execution failed."
            )

        else:

            st.session_state.scan_result = result

            status.success(
                "✅ Security Scan Completed Successfully!"
            )

    except Exception as error:

        st.exception(error)

# ---------------------------------------------------------
# Results Placeholder
# ---------------------------------------------------------

st.markdown("---")

st.markdown(
    '<div class="section-title">Scan Results</div>',
    unsafe_allow_html=True,
)

if st.session_state.scan_result is None:

    st.info(
        "No scan has been executed yet."
    )

else:

    result = st.session_state.scan_result

    # ---------------------------------------------------------
# Dashboard Overview
# ---------------------------------------------------------

st.markdown("---")

st.markdown(
    '<div class="section-title">📊 Overview</div>',
    unsafe_allow_html=True,
)

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Endpoints",
        len(result.discovered_endpoints),
    )

with col2:

    st.metric(
        "Test Plans",
        len(result.test_plans),
    )

with col3:

    st.metric(
        "Risk Reports",
        len(result.risk_reports),
    )

with col4:

    st.metric(
        "Scan Time",
        f"{result.scan_duration}s",
    )

# ---------------------------------------------------------
# Endpoint Explorer
# ---------------------------------------------------------

st.markdown("---")

st.markdown(
    '<div class="section-title">🌐 Endpoint Explorer</div>',
    unsafe_allow_html=True,
)

if result.discovered_endpoints:

    endpoint_rows = []

    for endpoint in result.discovered_endpoints:

        endpoint_rows.append({

            "Method": endpoint.method,

            "Path": endpoint.path,

            "Summary": endpoint.summary,

        })

    st.dataframe(
        endpoint_rows,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info(
        "No endpoints discovered."
    )

# ---------------------------------------------------------
# Risk Analysis
# ---------------------------------------------------------

st.markdown("---")

st.markdown(
    '<div class="section-title">⚠ Risk Analysis</div>',
    unsafe_allow_html=True,
)

if result.risk_reports:

    for report in result.risk_reports:

        with st.expander(
            report.endpoint,
            expanded=False,
        ):

            st.write(
                f"Overall Score: {report.overall_score}"
            )

            st.write(
                f"Overall Rating: {report.overall_rating}"
            )

            st.write(
                f"Findings: {len(report.findings)}"
            )

else:

    st.info(
        "No risk reports generated."
    )

# ---------------------------------------------------------
# AI Security Analysis
# ---------------------------------------------------------

st.markdown("---")

st.markdown(
    '<div class="section-title">🤖 AI Security Analysis</div>',
    unsafe_allow_html=True,
)

if result.ai_analyses:

    for analysis in result.ai_analyses:

        with st.expander(
            analysis.executive_summary[:80] + "...",
            expanded=False,
        ):

            st.subheader(
                "Executive Summary"
            )

            st.write(
                analysis.executive_summary
            )

            st.subheader(
                "Business Impact"
            )

            st.write(
                analysis.business_impact
            )

            st.subheader(
                "Recommended Remediation"
            )

            st.write(
                analysis.remediation_plan
            )

else:

    st.info(
        "No AI analyses available."
    )

# ---------------------------------------------------------
# Risk Distribution
# ---------------------------------------------------------

st.markdown("---")

st.markdown(
    '<div class="section-title">📊 Risk Distribution</div>',
    unsafe_allow_html=True,
)

if result.risk_reports:

    ratings = {}

    for report in result.risk_reports:

        rating = report.overall_rating

        ratings[rating] = ratings.get(rating, 0) + 1

    chart_data = pd.DataFrame(
        {
            "Rating": list(ratings.keys()),
            "Endpoints": list(ratings.values()),
        }
    )

    st.bar_chart(
        chart_data.set_index("Rating")
    )

else:

    st.info("No risk data available.")

# ---------------------------------------------------------
# Professional Reports
# ---------------------------------------------------------

st.markdown("---")

st.markdown(
    '<div class="section-title">📄 Professional Reports</div>',
    unsafe_allow_html=True,
)

if result.final_reports:

    report_options = [
        report.endpoint for report in result.final_reports
    ]

    selected_report = st.selectbox(
        "Select Endpoint Report",
        report_options,
    )

    report = next(
        r for r in result.final_reports
        if r.endpoint == selected_report
    )

    st.subheader("Executive Summary")
    st.write(report.executive_summary)

    st.subheader("Technical Analysis")
    st.write(report.technical_analysis)

    st.subheader("Business Impact")
    st.write(report.business_impact)

    st.subheader("Recommended Remediation")
    st.write(report.remediation)

    st.subheader("Secure Coding Advice")
    st.write(report.secure_coding)

    st.subheader("Conclusion")
    st.write(report.conclusion)

else:

    st.info("No reports available.")

# ---------------------------------------------------------
# Export Reports
# ---------------------------------------------------------

st.markdown("---")

st.markdown(
    '<div class="section-title">⬇ Export Reports</div>',
    unsafe_allow_html=True,
)

json_data = json.dumps(
    [
        report.__dict__
        for report in result.final_reports
    ],
    indent=4,
    default=str,
)

st.download_button(
    "📥 Download JSON Report",
    json_data,
    file_name="api_sentinel_report.json",
    mime="application/json",
)

markdown_report = ""

for report in result.final_reports:

    markdown_report += f"# {report.endpoint}\n\n"

    markdown_report += f"## Executive Summary\n{report.executive_summary}\n\n"

    markdown_report += f"## Technical Analysis\n{report.technical_analysis}\n\n"

    markdown_report += f"## Business Impact\n{report.business_impact}\n\n"

    markdown_report += f"## Remediation\n{report.remediation}\n\n"

    markdown_report += "---\n\n"

st.download_button(
    "📄 Download Markdown Report",
    markdown_report,
    file_name="api_sentinel_report.md",
    mime="text/markdown",
)

# ---------------------------------------------------------
# Footer
# ---------------------------------------------------------

st.markdown("---")

st.caption(
    "API Sentinel AI • Built with Streamlit • AI Powered API Security Platform"
)