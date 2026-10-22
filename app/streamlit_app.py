
"""CloudGuard AI — AWS IAM policy risk analysis dashboard."""
from __future__ import annotations

import json

import streamlit as st

from src.agent import explain_prediction
from src.data_loader import PolicyValidationError
from src.predict import predict_policy


st.set_page_config(
    page_title="CloudGuard AI",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .block-container {
        max-width: 1200px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }
    .hero {
        padding: 1.5rem;
        border: 1px solid rgba(128,128,128,.3);
        border-radius: 16px;
        margin-bottom: 1.5rem;
    }
    .muted {
        color: #808080;
        font-size: .9rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ CloudGuard AI")
st.markdown(
    "### AWS IAM Policy Risk Analyzer\n"
    "Analyze IAM policies using machine learning and rule-based security checks."
)

st.markdown(
    """
    <div class="hero">
      <strong>Analyze before you deploy.</strong><br>
      Paste a policy or upload a JSON file to inspect detected risks,
      supporting evidence, and recommended remediations.
      <div class="muted">
        Local analysis · No AWS credentials required · No external AI API required
      </div>
    </div>
    """,
    unsafe_allow_html=True,
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
)

policy_text = ""

if input_method == "Paste JSON":
    policy_text = st.text_area(
        "IAM policy JSON",
        value=json.dumps(EXAMPLE_POLICY, indent=2),
        height=300,
        help="Replace the example with the IAM policy you want to analyze.",
    )
else:
    uploaded_file = st.file_uploader(
        "Upload an IAM policy",
        type=["json"],
    )
    if uploaded_file is not None:
        try:
            policy_text = uploaded_file.getvalue().decode("utf-8")
            st.code(policy_text, language="json")
        except UnicodeDecodeError:
            st.error("The file must use UTF-8 text encoding.")

analyze = st.button(
    "Analyze policy",
    type="primary",
    use_container_width=True,
)

if analyze:
    if not policy_text.strip():
        st.error("Paste a policy or upload a JSON file first.")
    else:
        try:
            policy = json.loads(policy_text)

            with st.spinner("Analyzing IAM policy..."):
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

if "analysis_result" in st.session_state:
    result = st.session_state["analysis_result"]
    report = st.session_state["analysis_report"]

    st.divider()
    st.header("Analysis results")

    prediction = report["prediction"]
    severity = report["highest_severity"]

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("ML prediction", prediction.upper())

    with col2:
        st.metric("Highest rule severity", severity)

    with col3:
        st.metric(
            "Model risk probability",
            f"{report['risk_probability']:.1%}",
        )

    if severity in ("CRITICAL", "HIGH"):
        st.error(report["summary"])
    elif prediction == "misconfigured":
        st.warning(report["summary"])
    else:
        st.success(report["summary"])

    st.subheader("Findings and recommendations")

    if report["findings"]:
        for index, finding in enumerate(report["findings"], start=1):
            with st.expander(
                f"{finding['severity']} — {finding['rule_id']}: "
                f"{finding['title']}",
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

    with st.expander("Technical details"):
        st.markdown("**Extracted model features**")
        st.json(result["features"])

        st.markdown("**Model limitations**")
        st.write(report["limitations"])

    st.download_button(
        "Download analysis report (JSON)",
        data=json.dumps(report, indent=2),
        file_name="cloudguard_analysis_report.json",
        mime="application/json",
        use_container_width=True,
    )

st.divider()
st.caption(
    "CloudGuard AI is an educational decision-support prototype. "
    "It is not an official AWS security validator. Always review IAM "
    "permissions and validate findings before making production changes."
)
