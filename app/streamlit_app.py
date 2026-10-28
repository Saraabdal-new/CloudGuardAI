
"""CloudGuard AI — AWS IAM policy risk analysis dashboard."""
from __future__ import annotations

import json

import streamlit as st

from src.agent import explain_prediction
from src.data_loader import PolicyValidationError
from src.predict import predict_policy


# ---------------------------------------------------------
# Page configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="CloudGuard AI | IAM Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------
# Visual identity: Dark Security + violet accent
# ---------------------------------------------------------
st.markdown(
    """
    <style>
    :root {
        --cg-bg: #080B14;
        --cg-panel: #101625;
        --cg-panel-light: #151D30;
        --cg-border: #263047;
        --cg-text: #F1F5F9;
        --cg-muted: #94A3B8;
        --cg-violet: #A78BFA;
        --cg-violet-dark: #7C3AED;
        --cg-green: #34D399;
        --cg-red: #F87171;
    }

    .stApp {
        background:
            radial-gradient(ellipse at 80% 0%, #17142B 0%, transparent 36%),
            var(--cg-bg);
        color: var(--cg-text);
    }

    [data-testid="stHeader"] {
        background: rgba(8, 11, 20, 0.85);
    }

    [data-testid="stSidebar"] {
        background: #0C1120;
        border-right: 1px solid var(--cg-border);
    }

    [data-testid="stSidebar"] > div:first-child {
        background: transparent;
    }

    .block-container {
        max-width: 1440px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    h1, h2, h3 {
        color: var(--cg-text) !important;
        letter-spacing: -0.025em;
    }

    p, label, li {
        color: #CBD5E1;
    }

    .cg-brand {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 10px;
    }

    .cg-brand-icon {
        display: flex;
        align-items: center;
        justify-content: center;
        min-width: 46px;
        height: 46px;
        border-radius: 14px;
        background: linear-gradient(135deg, #7C3AED, #4F46E5);
        color: white;
        font-size: 24px;
        box-shadow: 0 0 28px rgba(124, 58, 237, 0.2);
    }

    .cg-brand-name {
        font-size: 1.35rem;
        font-weight: 800;
        color: #F8FAFC;
        line-height: 1.25;
    }

    .cg-brand-subtitle {
        font-size: 0.72rem;
        color: var(--cg-muted);
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-top: 3px;
    }

    .cg-eyebrow {
        color: var(--cg-violet);
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.14em;
        margin-bottom: 0.5rem;
    }

    .cg-hero {
        background: linear-gradient(
            120deg,
            rgba(124, 58, 237, 0.13),
            rgba(16, 22, 37, 0.92) 55%,
            rgba(52, 211, 153, 0.05)
        );
        border: 1px solid #30294B;
        border-radius: 20px;
        padding: 28px;
        margin: 10px 0 24px 0;
    }

    .cg-hero-title {
        font-size: clamp(1.8rem, 3vw, 2.65rem);
        font-weight: 800;
        line-height: 1.15;
        letter-spacing: -0.045em;
        color: #F8FAFC;
        margin: 0 0 12px 0;
    }

    .cg-gradient-text {
        background: linear-gradient(90deg, #C4B5FD, #A78BFA, #6EE7B7);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
    }

    .cg-hero-description {
        color: #AEBBD0;
        font-size: 1rem;
        line-height: 1.7;
        max-width: 760px;
    }

    .cg-pills {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 18px;
    }

    .cg-pill {
        display: inline-block;
        padding: 6px 10px;
        border: 1px solid #344057;
        border-radius: 999px;
        background: rgba(15, 23, 42, 0.7);
        color: #C7D2E3;
        font-size: 0.76rem;
    }

    .cg-section-label {
        color: var(--cg-violet);
        text-transform: uppercase;
        letter-spacing: 0.12em;
        font-weight: 700;
        font-size: 0.72rem;
        margin-bottom: 6px;
    }

    .cg-card {
        background: linear-gradient(145deg, #141B2B, #0E1422);
        border: 1px solid var(--cg-border);
        border-radius: 16px;
        padding: 18px;
        height: 100%;
    }

    .cg-card-label {
        color: var(--cg-muted);
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        font-weight: 700;
    }

    .cg-card-value {
        font-size: 1.4rem;
        font-weight: 800;
        color: #F8FAFC;
        margin-top: 9px;
        overflow-wrap: anywhere;
    }

    .cg-card-caption {
        color: var(--cg-muted);
        font-size: 0.78rem;
        margin-top: 6px;
        line-height: 1.5;
    }

    .cg-status {
        display: inline-block;
        padding: 5px 10px;
        border-radius: 7px;
        font-size: 0.72rem;
        font-weight: 800;
        letter-spacing: 0.06em;
        border: 1px solid;
    }

    .cg-status-green {
        color: #6EE7B7;
        background: rgba(16, 185, 129, 0.09);
        border-color: rgba(52, 211, 153, 0.3);
    }

    .cg-status-violet {
        color: #C4B5FD;
        background: rgba(139, 92, 246, 0.10);
        border-color: rgba(167, 139, 250, 0.3);
    }

    .cg-status-red {
        color: #FCA5A5;
        background: rgba(239, 68, 68, 0.09);
        border-color: rgba(248, 113, 113, 0.3);
    }

    .stButton > button[kind="primary"] {
        background: linear-gradient(100deg, #7C3AED, #6D28D9);
        color: #FFFFFF;
        border: 1px solid #8B5CF6;
        border-radius: 10px;
        font-weight: 700;
        min-height: 46px;
        transition: all 0.2s ease;
    }

    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(100deg, #8B5CF6, #7C3AED);
        border-color: #C4B5FD;
        box-shadow: 0 0 22px rgba(139, 92, 246, 0.2);
    }

    .stButton > button[kind="secondary"] {
        border: 1px solid #344057;
        border-radius: 10px;
    }

    [data-testid="stTextArea"] textarea {
        background: #0A1020;
        color: #D8E2F0;
        border: 1px solid #303B53;
        border-radius: 12px;
        font-family: Consolas, "Courier New", monospace;
        font-size: 0.9rem;
        line-height: 1.6;
    }

    [data-testid="stTextArea"] textarea:focus {
        border-color: var(--cg-violet);
        box-shadow: 0 0 0 1px var(--cg-violet);
    }

    [data-testid="stFileUploader"] {
        background: rgba(16, 22, 37, 0.75);
        border: 1px dashed #45516B;
        border-radius: 12px;
        padding: 12px;
    }

    [data-testid="stMetric"] {
        background: #111827;
        border: 1px solid #29344B;
        border-radius: 13px;
        padding: 16px;
    }

    [data-testid="stMetricLabel"] {
        color: #A5B4C8;
    }

    [data-testid="stMetricValue"] {
        color: #F8FAFC;
    }

    [data-testid="stExpander"] {
        background: rgba(16, 22, 37, 0.8);
        border: 1px solid var(--cg-border);
        border-radius: 12px;
    }

    [data-testid="stAlert"] {
        border-radius: 12px;
    }

    hr {
        border-color: #263047;
    }

    .cg-sidebar-note {
        background: #111827;
        border: 1px solid #29344B;
        border-radius: 12px;
        padding: 13px;
        color: #AEBBD0;
        font-size: 0.82rem;
        line-height: 1.6;
    }

    .cg-footer {
        color: #718096;
        font-size: 0.78rem;
        line-height: 1.7;
        text-align: center;
        border-top: 1px solid #263047;
        padding-top: 20px;
        margin-top: 35px;
    }

    @media (max-width: 768px) {
        .block-container {
            padding-top: 1rem;
        }

        .cg-hero {
            padding: 20px;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------
# Sidebar
# ---------------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <div class="cg-brand">
            <div class="cg-brand-icon">🛡</div>
            <div>
                <div class="cg-brand-name">CloudGuard AI</div>
                <div class="cg-brand-subtitle">IAM Security Analyzer</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    st.markdown('<div class="cg-section-label">Workspace</div>',
                unsafe_allow_html=True)
    st.markdown("**Policy analysis**")
    st.caption("Inspect AWS IAM permissions and identify risky configurations.")

    st.divider()

    st.markdown('<div class="cg-section-label">Analysis engine</div>',
                unsafe_allow_html=True)
    st.markdown(
        '<span class="cg-status cg-status-green">● RULE-BASED SCANNER</span>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<span class="cg-status cg-status-violet">● ML PREDICTION</span>',
        unsafe_allow_html=True,
    )

    st.write("")
    st.markdown(
        """
        <div class="cg-sidebar-note">
            <strong>Privacy by design</strong><br>
            Policies are analyzed locally by this application.
            No AWS credentials or external AI API are required.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")
    st.caption("CloudGuard AI · Educational prototype · v1.0")


# ---------------------------------------------------------
# Header
# ---------------------------------------------------------
st.markdown(
    '<div class="cg-eyebrow">CLOUD SECURITY / POLICY INTELLIGENCE</div>',
    unsafe_allow_html=True,
)
st.markdown(
    """
    <div class="cg-hero">
        <div class="cg-hero-title">
            Analyze before you <span class="cg-gradient-text">deploy.</span>
        </div>
        <div class="cg-hero-description">
            Evaluate AWS IAM policies with rule-based security checks
            and machine-learning risk prediction. Inspect findings,
            supporting evidence, and actionable remediation guidance.
        </div>
        <div class="cg-pills">
            <span class="cg-pill">Local analysis</span>
            <span class="cg-pill">No AWS credentials required</span>
            <span class="cg-pill">Rule-based + ML</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------
# Policy input
# ---------------------------------------------------------
st.markdown(
    '<div class="cg-section-label">01 / INPUT</div>',
    unsafe_allow_html=True,
)
st.subheader("Analyze an IAM policy")
st.caption(
    "Paste a JSON policy or upload a .json file. "
    "Review the content before starting the analysis."
)

EXAMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    ],
}

input_method = st.radio(
    "Policy input method",
    ["Paste JSON", "Upload JSON file"],
    horizontal=True,
    label_visibility="collapsed",
)

policy_text = ""
input_error: str | None = None

if input_method == "Paste JSON":
    policy_text = st.text_area(
        "IAM policy JSON",
        value=json.dumps(EXAMPLE_POLICY, indent=2),
        height=280,
        help="Replace the example with the IAM policy you want to analyze.",
    )
else:
    uploaded_file = st.file_uploader(
        "Upload an IAM policy",
        type=["json"],
        help="Choose a UTF-8 encoded JSON policy file.",
    )

    if uploaded_file is not None:
        try:
            policy_text = uploaded_file.getvalue().decode("utf-8")
            st.success(f"File loaded: {uploaded_file.name}")
            with st.expander("Preview uploaded JSON"):
                st.code(policy_text, language="json")
        except UnicodeDecodeError:
            input_error = "The file must use UTF-8 text encoding."

if input_error:
    st.error(input_error)

analyze = st.button(
    "Analyze policy",
    type="primary",
    use_container_width=True,
    disabled=bool(input_error),
    help="Validate the JSON and run the rule-based scanner and ML model.",
)


# ---------------------------------------------------------
# Analysis: preserve the existing prediction pipeline
# ---------------------------------------------------------
if analyze:
    # Never display a previous report after a new attempt.
    st.session_state.pop("analysis_result", None)
    st.session_state.pop("analysis_report", None)

    if input_error:
        st.error(input_error)
    elif not policy_text.strip():
        st.error("Paste a policy or upload a JSON file first.")
    else:
        try:
            policy = json.loads(policy_text)

            with st.spinner("Validating policy and running analysis..."):
                result = predict_policy(policy)
                report = explain_prediction(result)

            st.session_state["analysis_result"] = result
            st.session_state["analysis_report"] = report

        except json.JSONDecodeError as exc:
            st.error(
                f"Invalid JSON: {exc.msg} "
                f"(line {exc.lineno}, column {exc.colno})."
            )
        except (PolicyValidationError, ValueError) as exc:
            st.error(f"Policy validation failed: {exc}")
        except FileNotFoundError as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(
                f"Analysis failed ({type(exc).__name__}): {exc}"
            )


# ---------------------------------------------------------
# Results
# ---------------------------------------------------------
if "analysis_result" in st.session_state:
    result = st.session_state["analysis_result"]
    report = st.session_state["analysis_report"]

    prediction = report["prediction"]
    severity = report["highest_severity"]
    risk_probability = report["risk_probability"]
    findings = report["findings"]

    st.divider()
    st.markdown(
        '<div class="cg-section-label">02 / SECURITY ASSESSMENT</div>',
        unsafe_allow_html=True,
    )
    st.subheader("Analysis results")

    status_class = (
        "cg-status-red"
        if prediction == "misconfigured"
        else "cg-status-green"
    )
    status_label = prediction.upper()

    st.markdown(
        f'<span class="cg-status {status_class}">'
        f'● {status_label}</span>',
        unsafe_allow_html=True,
    )
    st.write("")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "ML prediction",
            prediction.upper(),
            help="Classification produced by the trained model.",
        )

    with col2:
        st.metric(
            "Highest rule severity",
            severity,
            help="Highest severity among findings produced by the scanner.",
        )

    with col3:
        st.metric(
            "Model risk probability",
            f"{risk_probability:.1%}",
            help=(
                "Model-estimated risk probability. "
                "This is not a guarantee of security."
            ),
        )

    if severity in ("CRITICAL", "HIGH"):
        st.error(report["summary"])
    elif prediction == "misconfigured":
        st.warning(report["summary"])
    else:
        st.success(report["summary"])

    # Findings and remediations
    st.markdown(
        '<div class="cg-section-label">03 / FINDINGS</div>',
        unsafe_allow_html=True,
    )
    st.subheader("Findings and recommendations")

    if findings:
        for index, finding in enumerate(findings, start=1):
            with st.expander(
                f"{finding['severity']}  |  "
                f"{finding['rule_id']}: {finding['title']}",
                expanded=(index == 1),
            ):
                st.markdown("**Why this matters**")
                st.write(finding["risk"])

                st.markdown("**Recommended remediation**")
                st.write(finding["recommendation"])

                st.markdown("**Evidence**")
                st.code(finding["evidence"], language="json")
    else:
        st.info(
            "No findings were produced by the current rule-based scanner. "
            "This does not guarantee that the policy is secure."
        )

    # Technical details
    with st.expander("Technical details and model limitations"):
        st.markdown("**Extracted model features**")
        st.json(result["features"])

        st.markdown("**Model limitations**")
        st.write(report["limitations"])

    # Report download
    report_json = json.dumps(report, indent=2, ensure_ascii=False)
    st.download_button(
        "Download analysis report (JSON)",
        data=report_json,
        file_name="cloudguard_analysis_report.json",
        mime="application/json",
        use_container_width=True,
    )


# ---------------------------------------------------------
# Footer
# ---------------------------------------------------------
st.markdown(
    """
    <div class="cg-footer">
        <strong>CloudGuard AI</strong> · AWS IAM Policy Risk Analyzer<br>
        Educational decision-support prototype. Not an official AWS
        security validator. Review IAM permissions and validate findings
        before making production changes.
    </div>
    """,
    unsafe_allow_html=True,
)
