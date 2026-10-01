"""
Streamlit Cyber Threat Intelligence Dashboard - Phase 11
Distributed Cyber Threat Intelligence Platform

A full-featured, multi-page Streamlit application that visualises threat
intelligence drawn live from MongoDB collections populated by Phase 10.

Pages
-----
1. 🏠 Overview & Security KPIs
2. 📊 Threat Analytics
3. 🌐 IP Threat Intelligence
4. 🤖 ML Intrusion Predictions
5. 🖥️ Cluster Status & Health

Run:
    streamlit run dashboard/app.py
"""

import sys
import json
from pathlib import Path
from datetime import datetime

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

# ---------------------------------------------------------------------------
# Project root on sys.path so config.settings is importable
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import MONGO_CONFIG, get_mongo_client

# ---------------------------------------------------------------------------
# Page configuration (must be first Streamlit call)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberShield | Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Global CSS — dark premium theme
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    /* ── Global font & background ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

    .stApp { background: #0a0e1a; color: #e2e8f0; }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1226 0%, #111827 100%);
        border-right: 1px solid #1e293b;
    }
    [data-testid="stSidebar"] .stRadio label { color: #94a3b8 !important; }

    /* ── Metric cards ── */
    [data-testid="metric-container"] {
        background: linear-gradient(135deg, #111827 0%, #1e293b 100%);
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 1.2rem 1.4rem;
    }
    [data-testid="metric-container"] label { color: #64748b !important; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; }
    [data-testid="metric-container"] [data-testid="stMetricValue"] { color: #38bdf8 !important; font-size: 1.8rem; font-weight: 700; }
    [data-testid="metric-container"] [data-testid="stMetricDelta"] { font-size: 0.78rem; }

    /* ── Section headers ── */
    .section-header {
        font-size: 1.05rem; font-weight: 600; color: #7dd3fc;
        border-left: 3px solid #0ea5e9; padding-left: 0.7rem;
        margin: 1.5rem 0 0.8rem;
    }

    /* ── Card wrapper ── */
    .card {
        background: linear-gradient(135deg, #111827 0%, #1a2236 100%);
        border: 1px solid #1e3a5f;
        border-radius: 14px;
        padding: 1.4rem;
        margin-bottom: 1rem;
    }

    /* ── Severity badges ── */
    .badge-critical { background:#7f1d1d; color:#fca5a5; padding:2px 10px; border-radius:999px; font-size:0.73rem; font-weight:600; }
    .badge-high     { background:#78350f; color:#fcd34d; padding:2px 10px; border-radius:999px; font-size:0.73rem; font-weight:600; }
    .badge-medium   { background:#1e3a5f; color:#7dd3fc; padding:2px 10px; border-radius:999px; font-size:0.73rem; font-weight:600; }
    .badge-low      { background:#14532d; color:#86efac; padding:2px 10px; border-radius:999px; font-size:0.73rem; font-weight:600; }

    /* ── DataFrame table ── */
    .stDataFrame { border-radius: 10px; overflow: hidden; }

    /* ── Divider ── */
    hr { border-color: #1e293b; }

    /* ── Alert/info boxes ── */
    .stAlert { border-radius: 10px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Colour palette shared by all charts
# ---------------------------------------------------------------------------
CHART_COLORS = [
    "#38bdf8", "#818cf8", "#34d399", "#fb923c",
    "#f472b6", "#a78bfa", "#22d3ee", "#4ade80",
    "#fbbf24", "#f87171",
]

ATTACK_COLORS = {
    "BENIGN":     "#34d399",
    "DDoS":       "#f87171",
    "PortScan":   "#fb923c",
    "BruteForce": "#818cf8",
    "Botnet":     "#f472b6",
}

SEVERITY_COLORS = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#38bdf8",
    "Low":      "#34d399",
}


# ---------------------------------------------------------------------------
# MongoDB helpers
# ---------------------------------------------------------------------------

@st.cache_resource(show_spinner=False)
def _mongo_client():
    try:
        return get_mongo_client(timeout_ms=8_000)
    except Exception:
        return None


def _get_collection(collection_name: str) -> list:
    """Return all documents from a MongoDB collection as a list of dicts."""
    client = _mongo_client()
    if client is None:
        return []
    try:
        db = client[MONGO_CONFIG["db_name"]]
        docs = list(db[collection_name].find({}, {"_id": 0}))
        return docs
    except Exception:
        return []


@st.cache_data(ttl=60, show_spinner=False)
def load_attack_stats() -> pd.DataFrame:
    return pd.DataFrame(_get_collection(MONGO_CONFIG["collections"]["attack_stats"]))


@st.cache_data(ttl=60, show_spinner=False)
def load_protocol_stats() -> pd.DataFrame:
    return pd.DataFrame(_get_collection("protocol_stats"))


@st.cache_data(ttl=60, show_spinner=False)
def load_hourly_stats() -> pd.DataFrame:
    return pd.DataFrame(_get_collection("hourly_stats"))


@st.cache_data(ttl=60, show_spinner=False)
def load_timeline() -> pd.DataFrame:
    return pd.DataFrame(_get_collection(MONGO_CONFIG["collections"]["timeline_stats"]))


@st.cache_data(ttl=60, show_spinner=False)
def load_ip_reputation() -> pd.DataFrame:
    return pd.DataFrame(_get_collection(MONGO_CONFIG["collections"]["ip_reputation"]))


@st.cache_data(ttl=60, show_spinner=False)
def load_ip_threat_freq() -> pd.DataFrame:
    return pd.DataFrame(_get_collection("ip_threat_frequency"))


@st.cache_data(ttl=60, show_spinner=False)
def load_predictions() -> pd.DataFrame:
    return pd.DataFrame(_get_collection(MONGO_CONFIG["collections"]["predictions"]))


@st.cache_data(ttl=300, show_spinner=False)
def load_model_metrics() -> dict:
    docs = _get_collection("model_metrics")
    return docs[0] if docs else {}


@st.cache_data(ttl=60, show_spinner=False)
def load_severity_stats() -> pd.DataFrame:
    return pd.DataFrame(_get_collection("severity_stats"))


# ---------------------------------------------------------------------------
# Demo / synthetic fallback (when MongoDB is offline or empty)
# ---------------------------------------------------------------------------

def _demo_attack_df() -> pd.DataFrame:
    return pd.DataFrame({
        "attack_type":       ["BENIGN", "DDoS", "PortScan", "BruteForce", "Botnet"],
        "total_flows":       [86432, 42180, 31560, 18720, 7340],
        "pct_share":         [46.1, 22.5, 16.8, 10.0, 3.9],
        "avg_severity_score":[0.0,   4.0,   2.0,   3.0,  3.5],
        "total_bytes_gb":    [12.4,  8.7,   4.1,   2.8,  0.9],
    })


def _demo_hourly_df() -> pd.DataFrame:
    import random; random.seed(7)
    hours = list(range(24))
    total = [random.randint(3000, 8000) for _ in hours]
    attacks = [int(t * random.uniform(0.2, 0.7)) for t in total]
    return pd.DataFrame({
        "hour":           hours,
        "total_flows":    total,
        "attack_flows":   attacks,
        "benign_flows":   [t - a for t, a in zip(total, attacks)],
        "attack_rate_pct":[round(a / t * 100, 1) for a, t in zip(attacks, total)],
    })


def _demo_ip_rep_df() -> pd.DataFrame:
    ips = [f"192.168.{i}.{j}" for i in range(1, 6) for j in range(1, 11)]
    import random; random.seed(42)
    return pd.DataFrame({
        "source_ip":           ips,
        "total_flows":         [random.randint(50, 3000) for _ in ips],
        "attack_count":        [random.randint(0, 500) for _ in ips],
        "unique_destinations": [random.randint(1, 30) for _ in ips],
        "risk_score":          [random.randint(5, 100) for _ in ips],
        "risk_level":          [random.choice(["Low","Medium","High","Critical"]) for _ in ips],
        "recommended_action":  ["Standard Network Monitoring"] * len(ips),
    }).sort_values("risk_score", ascending=False).reset_index(drop=True)


def _demo_predictions_df() -> pd.DataFrame:
    import random; random.seed(3)
    attacks = ["BENIGN", "DDoS", "PortScan", "BruteForce", "Botnet"]
    n = 50
    actual  = [random.choice(attacks) for _ in range(n)]
    pred    = [a if random.random() > 0.25 else random.choice(attacks) for a in actual]
    return pd.DataFrame({
        "source_ip":       [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(n)],
        "actual_attack":   actual,
        "predicted_attack":pred,
        "confidence":      [round(random.uniform(55, 99), 2) for _ in range(n)],
    })


def _demo_model_metrics() -> dict:
    return {
        "decision_tree": {"accuracy": 0.5094, "f1_score": 0.4869,
                          "precision": 0.5379, "recall": 0.5094, "training_time_s": 4.67},
        "random_forest": {"accuracy": 0.5198, "f1_score": 0.4991,
                          "precision": 0.5121, "recall": 0.5198, "training_time_s": 2.96},
    }


# ---------------------------------------------------------------------------
# Utility: ensure DataFrame is not empty, else use demo data
# ---------------------------------------------------------------------------

def _or_demo(df: pd.DataFrame, demo_fn) -> tuple[pd.DataFrame, bool]:
    if df is not None and not df.empty:
        return df, False
    return demo_fn(), True


# ---------------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------------

def _sidebar() -> str:
    with st.sidebar:
        st.markdown(
            """
            <div style='text-align:center; padding: 1rem 0 0.5rem;'>
                <div style='font-size:2.4rem;'>🛡️</div>
                <div style='font-size:1.1rem; font-weight:700; color:#38bdf8;'>CyberShield</div>
                <div style='font-size:0.72rem; color:#64748b; letter-spacing:0.1em;'>
                    THREAT INTELLIGENCE PLATFORM
                </div>
            </div>
            <hr style='border-color:#1e293b; margin:0.8rem 0;'>
            """,
            unsafe_allow_html=True,
        )

        page = st.radio(
            "Navigation",
            [
                "🏠 Overview & KPIs",
                "📊 Threat Analytics",
                "🌐 IP Threat Intelligence",
                "🤖 ML Predictions",
                "🖥️ Cluster Health",
            ],
            label_visibility="collapsed",
        )

        st.markdown("<hr style='border-color:#1e293b;'>", unsafe_allow_html=True)
        st.markdown(
            f"""
            <div style='font-size:0.7rem; color:#475569; text-align:center;'>
                Last refreshed<br>
                <span style='color:#7dd3fc;'>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.button("🔄 Refresh Data", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

    return page


# ===========================================================================
# Page 1 — Overview & KPIs
# ===========================================================================

def page_overview():
    st.markdown("## 🏠 Security Overview & KPIs")
    st.markdown(
        "<p style='color:#64748b;'>Real-time threat posture from CICIDS2017 network logs processed "
        "through the distributed Spark/ML pipeline.</p>",
        unsafe_allow_html=True,
    )

    attack_df, demo = _or_demo(load_attack_stats(), _demo_attack_df)
    ip_df, _        = _or_demo(load_ip_reputation(), _demo_ip_rep_df)

    if demo:
        st.info("ℹ️ MongoDB unavailable — showing synthetic demo data.", icon="ℹ️")

    # ── KPI row ──────────────────────────────────────────────────────────
    total_flows   = int(attack_df["total_flows"].sum()) if "total_flows" in attack_df else 0
    attack_flows  = int(attack_df.loc[attack_df["attack_type"] != "BENIGN", "total_flows"].sum()) if "total_flows" in attack_df else 0
    benign_flows  = total_flows - attack_flows
    attack_pct    = round(attack_flows / total_flows * 100, 1) if total_flows else 0
    critical_ips  = int((ip_df["risk_level"] == "Critical").sum()) if "risk_level" in ip_df else 0
    top_attack    = (
        attack_df.loc[attack_df["attack_type"] != "BENIGN"]
        .sort_values("total_flows", ascending=False)["attack_type"].iloc[0]
        if not attack_df.empty and "attack_type" in attack_df else "N/A"
    )

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("🔍 Total Events Analysed",  f"{total_flows:,}")
    c2.metric("⚠️ Attacks Detected",        f"{attack_flows:,}", f"{attack_pct}% of traffic", delta_color="inverse")
    c3.metric("✅ Benign Flows",            f"{benign_flows:,}")
    c4.metric("🔴 Critical-Risk IPs",       f"{critical_ips:,}", delta_color="inverse")
    c5.metric("🏴 Top Attack Vector",       top_attack)

    st.markdown("<hr>", unsafe_allow_html=True)

    # ── Attack distribution donut ─────────────────────────────────────────
    col_left, col_right = st.columns([1.1, 1])

    with col_left:
        st.markdown("<div class='section-header'>Attack Type Distribution</div>", unsafe_allow_html=True)
        if not attack_df.empty and "attack_type" in attack_df:
            colors = [ATTACK_COLORS.get(a, "#64748b") for a in attack_df["attack_type"]]
            fig = px.pie(
                attack_df, names="attack_type", values="total_flows",
                hole=0.55,
                color="attack_type",
                color_discrete_map=ATTACK_COLORS,
            )
            fig.update_traces(textinfo="percent+label", textfont_size=12)
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                legend=dict(font=dict(color="#94a3b8"), bgcolor="rgba(0,0,0,0)"),
                margin=dict(t=20, b=20, l=10, r=10), height=320,
            )
            st.plotly_chart(fig, use_container_width=True)

    with col_right:
        st.markdown("<div class='section-header'>Attack Type Breakdown</div>", unsafe_allow_html=True)
        if not attack_df.empty:
            show_cols = [c for c in ["attack_type", "total_flows", "pct_share", "avg_severity_score"]
                         if c in attack_df.columns]
            st.dataframe(
                attack_df[show_cols].rename(columns={
                    "attack_type": "Attack Type",
                    "total_flows": "Flows",
                    "pct_share":   "Share %",
                    "avg_severity_score": "Avg Severity",
                }),
                use_container_width=True, hide_index=True,
            )

    # ── IP risk tier breakdown ─────────────────────────────────────────────
    st.markdown("<div class='section-header'>IP Risk Tier Distribution</div>", unsafe_allow_html=True)
    if not ip_df.empty and "risk_level" in ip_df.columns:
        tier_counts = ip_df["risk_level"].value_counts().reset_index()
        tier_counts.columns = ["Risk Level", "IP Count"]
        tier_order = ["Critical", "High", "Medium", "Low"]
        tier_counts["Risk Level"] = pd.Categorical(tier_counts["Risk Level"], categories=tier_order, ordered=True)
        tier_counts = tier_counts.sort_values("Risk Level")

        fig_bar = px.bar(
            tier_counts, x="Risk Level", y="IP Count",
            color="Risk Level",
            color_discrete_map=SEVERITY_COLORS,
            text="IP Count",
        )
        fig_bar.update_traces(textposition="outside", textfont_color="#e2e8f0")
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(color="#64748b"), yaxis=dict(color="#64748b", showgrid=False),
            legend_title_text="", margin=dict(t=20, b=20, l=10, r=10), height=260,
            showlegend=False,
        )
        st.plotly_chart(fig_bar, use_container_width=True)


# ===========================================================================
# Page 2 — Threat Analytics
# ===========================================================================

def page_threat_analytics():
    st.markdown("## 📊 Threat Analytics")

    hourly_df, demo = _or_demo(load_hourly_stats(), _demo_hourly_df)
    attack_df, _    = _or_demo(load_attack_stats(), _demo_attack_df)
    proto_df, _     = _or_demo(load_protocol_stats(), lambda: pd.DataFrame({
        "protocol":    ["TCP", "UDP", "ICMP"],
        "total_flows": [112000, 64000, 10230],
        "attack_count":[84000, 28000, 4000],
        "benign_count":[28000, 36000, 6230],
    }))

    if demo:
        st.info("ℹ️ MongoDB unavailable — showing synthetic demo data.", icon="ℹ️")

    # ── Hourly attack intensity ───────────────────────────────────────────
    st.markdown("<div class='section-header'>24-Hour Attack Intensity Timeline</div>", unsafe_allow_html=True)
    if not hourly_df.empty and "hour" in hourly_df.columns:
        hourly_df = hourly_df.sort_values("hour")
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=hourly_df["hour"], y=hourly_df.get("total_flows", []),
            name="Total Flows", fill="tozeroy",
            line=dict(color="#38bdf8", width=2),
            fillcolor="rgba(56,189,248,0.08)",
        ))
        if "attack_flows" in hourly_df.columns:
            fig.add_trace(go.Scatter(
                x=hourly_df["hour"], y=hourly_df["attack_flows"],
                name="Attack Flows", fill="tozeroy",
                line=dict(color="#f87171", width=2),
                fillcolor="rgba(248,113,113,0.15)",
            ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(title="Hour (UTC)", color="#64748b", dtick=2),
            yaxis=dict(title="Flow Count",  color="#64748b", showgrid=True,
                       gridcolor="#1e293b"),
            legend=dict(font=dict(color="#94a3b8"), bgcolor="rgba(0,0,0,0)"),
            margin=dict(t=20, b=40, l=10, r=10), height=300,
        )
        st.plotly_chart(fig, use_container_width=True)

    col_l, col_r = st.columns(2)

    # ── Protocol distribution ─────────────────────────────────────────────
    with col_l:
        st.markdown("<div class='section-header'>Protocol Distribution</div>", unsafe_allow_html=True)
        if not proto_df.empty and "protocol" in proto_df.columns:
            fig_proto = px.bar(
                proto_df.head(10), x="protocol", y="total_flows",
                color_discrete_sequence=["#818cf8"],
                text="total_flows",
            )
            fig_proto.update_traces(texttemplate="%{text:,}", textposition="outside")
            fig_proto.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(color="#64748b"), yaxis=dict(color="#64748b", showgrid=False),
                margin=dict(t=20, b=20, l=10, r=10), height=280,
                showlegend=False,
            )
            st.plotly_chart(fig_proto, use_container_width=True)

    # ── Attack severity sunburst ──────────────────────────────────────────
    with col_r:
        st.markdown("<div class='section-header'>Bytes by Attack Type</div>", unsafe_allow_html=True)
        if not attack_df.empty and "total_bytes_gb" in attack_df.columns:
            fig_bytes = px.bar(
                attack_df.sort_values("total_bytes_gb", ascending=True).tail(8),
                x="total_bytes_gb", y="attack_type",
                orientation="h",
                color="attack_type",
                color_discrete_map=ATTACK_COLORS,
            )
            fig_bytes.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(title="Gigabytes", color="#64748b"),
                yaxis=dict(color="#64748b", showgrid=False, title=""),
                margin=dict(t=20, b=20, l=10, r=10), height=280,
                showlegend=False,
            )
            st.plotly_chart(fig_bytes, use_container_width=True)


# ===========================================================================
# Page 3 — IP Threat Intelligence
# ===========================================================================

def page_ip_intelligence():
    st.markdown("## 🌐 IP Threat Intelligence")

    ip_rep_df, demo = _or_demo(load_ip_reputation(), _demo_ip_rep_df)
    ip_freq_df, _   = _or_demo(load_ip_threat_freq(), _demo_ip_rep_df)

    if demo:
        st.info("ℹ️ MongoDB unavailable — showing synthetic demo data.", icon="ℹ️")

    # ── Filters ────────────────────────────────────────────────────────────
    col_f1, col_f2 = st.columns([1, 3])
    with col_f1:
        severity_filter = st.multiselect(
            "Filter by Risk Level",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High"],
        )

    if severity_filter and "risk_level" in ip_rep_df.columns:
        filtered = ip_rep_df[ip_rep_df["risk_level"].isin(severity_filter)]
    else:
        filtered = ip_rep_df

    # ── Risk score scatter ────────────────────────────────────────────────
    st.markdown("<div class='section-header'>IP Risk Score Distribution</div>", unsafe_allow_html=True)
    if not filtered.empty and "risk_score" in filtered.columns:
        plot_df = filtered.head(100).copy()
        fig = px.scatter(
            plot_df,
            x="total_flows" if "total_flows" in plot_df.columns else plot_df.index,
            y="risk_score",
            color="risk_level",
            color_discrete_map=SEVERITY_COLORS,
            hover_data=["source_ip"] if "source_ip" in plot_df.columns else [],
            size="attack_count" if "attack_count" in plot_df.columns else None,
            size_max=24,
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(title="Total Flows", color="#64748b"),
            yaxis=dict(title="Risk Score (0-100)", color="#64748b",
                       showgrid=True, gridcolor="#1e293b"),
            legend=dict(font=dict(color="#94a3b8"), bgcolor="rgba(0,0,0,0)"),
            margin=dict(t=20, b=20, l=10, r=10), height=320,
        )
        st.plotly_chart(fig, use_container_width=True)

    # ── Top IPs table ─────────────────────────────────────────────────────
    st.markdown("<div class='section-header'>Top Threat Actors — IP Reputation Table</div>", unsafe_allow_html=True)
    if not filtered.empty:
        display_cols = [c for c in
                        ["source_ip", "risk_score", "risk_level", "attack_count",
                         "total_flows", "unique_destinations", "recommended_action"]
                        if c in filtered.columns]
        st.dataframe(
            filtered[display_cols].head(50).rename(columns={
                "source_ip":           "IP Address",
                "risk_score":          "Risk Score",
                "risk_level":          "Risk Level",
                "attack_count":        "Attacks",
                "total_flows":         "Total Flows",
                "unique_destinations": "Targets",
                "recommended_action":  "Recommended Action",
            }),
            use_container_width=True, hide_index=True,
        )
    else:
        st.warning("No IPs match the selected filters.")


# ===========================================================================
# Page 4 — ML Predictions
# ===========================================================================

def page_ml_predictions():
    st.markdown("## 🤖 ML Intrusion Detection Predictions")

    pred_df, demo = _or_demo(load_predictions(), _demo_predictions_df)
    metrics       = load_model_metrics() or _demo_model_metrics()

    if demo:
        st.info("ℹ️ MongoDB unavailable — showing synthetic demo data.", icon="ℹ️")

    # ── Model performance KPIs ────────────────────────────────────────────
    st.markdown("<div class='section-header'>Model Performance Benchmarks</div>", unsafe_allow_html=True)

    dt_m = metrics.get("decision_tree", {})
    rf_m = metrics.get("random_forest", {})

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🌲 DT Accuracy",   f"{dt_m.get('accuracy', 0)*100:.1f}%")
    c2.metric("🌲 DT F1-Score",   f"{dt_m.get('f1_score', 0):.4f}")
    c3.metric("🌳 RF Accuracy",   f"{rf_m.get('accuracy', 0)*100:.1f}%",
              delta=f"+{(rf_m.get('accuracy',0)-dt_m.get('accuracy',0))*100:.1f}%")
    c4.metric("🌳 RF F1-Score",   f"{rf_m.get('f1_score', 0):.4f}",
              delta=f"+{rf_m.get('f1_score',0)-dt_m.get('f1_score',0):.4f}")

    # ── Model comparison radar ────────────────────────────────────────────
    col_l, col_r = st.columns(2)
    with col_l:
        st.markdown("<div class='section-header'>DT vs RF Metric Comparison</div>", unsafe_allow_html=True)
        categories = ["Accuracy", "F1-Score", "Precision", "Recall"]
        dt_vals = [
            dt_m.get("accuracy", 0), dt_m.get("f1_score", 0),
            dt_m.get("precision", 0), dt_m.get("recall", 0),
        ]
        rf_vals = [
            rf_m.get("accuracy", 0), rf_m.get("f1_score", 0),
            rf_m.get("precision", 0), rf_m.get("recall", 0),
        ]
        fig_radar = go.Figure()
        fig_radar.add_trace(go.Scatterpolar(
            r=dt_vals + [dt_vals[0]], theta=categories + [categories[0]],
            fill="toself", name="Decision Tree",
            line_color="#818cf8", fillcolor="rgba(129,140,248,0.15)",
        ))
        fig_radar.add_trace(go.Scatterpolar(
            r=rf_vals + [rf_vals[0]], theta=categories + [categories[0]],
            fill="toself", name="Random Forest",
            line_color="#38bdf8", fillcolor="rgba(56,189,248,0.15)",
        ))
        fig_radar.update_layout(
            polar=dict(
                bgcolor="rgba(0,0,0,0)",
                radialaxis=dict(visible=True, range=[0, 1], color="#64748b",
                                gridcolor="#1e293b"),
                angularaxis=dict(color="#94a3b8"),
            ),
            paper_bgcolor="rgba(0,0,0,0)",
            legend=dict(font=dict(color="#94a3b8"), bgcolor="rgba(0,0,0,0)"),
            margin=dict(t=20, b=20, l=20, r=20), height=300,
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    # ── Actual vs Predicted confusion ────────────────────────────────────
    with col_r:
        st.markdown("<div class='section-header'>Actual vs Predicted Distribution</div>", unsafe_allow_html=True)
        if not pred_df.empty and "actual_attack" in pred_df.columns and "predicted_attack" in pred_df.columns:
            actual_counts = pred_df["actual_attack"].value_counts().reset_index()
            actual_counts.columns = ["Attack Type", "Count"]
            actual_counts["Source"] = "Actual"
            pred_counts = pred_df["predicted_attack"].value_counts().reset_index()
            pred_counts.columns = ["Attack Type", "Count"]
            pred_counts["Source"] = "Predicted"
            combined = pd.concat([actual_counts, pred_counts])

            fig_comp = px.bar(
                combined, x="Attack Type", y="Count", color="Source",
                barmode="group",
                color_discrete_map={"Actual": "#38bdf8", "Predicted": "#f472b6"},
            )
            fig_comp.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(color="#64748b"), yaxis=dict(color="#64748b", showgrid=False),
                legend=dict(font=dict(color="#94a3b8"), bgcolor="rgba(0,0,0,0)"),
                margin=dict(t=20, b=20, l=10, r=10), height=300,
            )
            st.plotly_chart(fig_comp, use_container_width=True)

    # ── Prediction sample table ───────────────────────────────────────────
    st.markdown("<div class='section-header'>Sample Intrusion Prediction Events</div>", unsafe_allow_html=True)
    if not pred_df.empty:
        show_cols = [c for c in ["source_ip", "actual_attack", "predicted_attack", "confidence"]
                     if c in pred_df.columns]
        st.dataframe(
            pred_df[show_cols].head(30).rename(columns={
                "source_ip":        "Source IP",
                "actual_attack":    "Actual",
                "predicted_attack": "Predicted",
                "confidence":       "Confidence %",
            }),
            use_container_width=True, hide_index=True,
        )


# ===========================================================================
# Page 5 — Cluster Health  (imported from cluster_health.py)
# ===========================================================================

def page_cluster_health():
    # Import and render the separate cluster health module
    try:
        from dashboard.cluster_health import render_cluster_health
        render_cluster_health()
    except ImportError:
        # Inline fallback if module path resolution differs
        _inline_cluster_health()


def _inline_cluster_health():
    """Inline cluster health rendering (fallback if import fails)."""
    st.markdown("## 🖥️ Cluster Status & Health")
    st.markdown(
        "<p style='color:#64748b;'>Live status of MongoDB shards, Hadoop HDFS nodes, "
        "and Apache Spark master/workers.</p>",
        unsafe_allow_html=True,
    )

    import subprocess

    col1, col2, col3 = st.columns(3)

    # ── MongoDB ────────────────────────────────────────────────────────
    with col1:
        st.markdown("<div class='section-header'>🍃 MongoDB Cluster</div>", unsafe_allow_html=True)
        try:
            client = get_mongo_client(timeout_ms=5_000)
            info   = client.admin.command("serverStatus")
            uptime_h = round(info.get("uptime", 0) / 3600, 1)
            conns    = info.get("connections", {}).get("current", "N/A")
            st.success("● Connected", icon="✅")
            st.metric("Uptime",            f"{uptime_h} h")
            st.metric("Active Connections", str(conns))
            client.close()
        except Exception as e:
            st.error(f"✗ Disconnected\n{e}", icon="🔴")

    # ── Hadoop HDFS ────────────────────────────────────────────────────
    with col2:
        st.markdown("<div class='section-header'>🐘 Hadoop HDFS</div>", unsafe_allow_html=True)
        try:
            result = subprocess.run(
                ["hdfs", "dfsadmin", "-report"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                st.success("● NameNode reachable", icon="✅")
                lines = result.stdout.split("\n")
                dn_count = sum(1 for l in lines if "Name:" in l)
                st.metric("Live DataNodes", str(dn_count))
                # Parse total / remaining capacity
                for line in lines:
                    if "DFS Remaining:" in line:
                        st.caption(f"Free: {line.split(':',1)[1].strip()}")
                    if "DFS Used%:" in line:
                        st.caption(f"Used: {line.split(':',1)[1].strip()}")
            else:
                st.warning("⚠ HDFS returned non-zero exit code.")
        except FileNotFoundError:
            st.warning("hdfs CLI not found on PATH.")
        except subprocess.TimeoutExpired:
            st.error("HDFS report timed out.", icon="🔴")
        except Exception as e:
            st.error(f"HDFS error: {e}", icon="🔴")

    # ── Spark ──────────────────────────────────────────────────────────
    with col3:
        st.markdown("<div class='section-header'>⚡ Apache Spark</div>", unsafe_allow_html=True)
        try:
            import requests as req
            from config.settings import SPARK_CONFIG
            master_host = SPARK_CONFIG["master_host"]
            resp = req.get(f"http://{master_host}:8080/json/", timeout=5)
            data = resp.json()
            workers     = len(data.get("workers", []))
            alive       = sum(1 for w in data.get("workers", []) if w.get("state") == "ALIVE")
            cores       = data.get("cores", "N/A")
            mem_gb      = round(data.get("memory", 0) / 1024, 1)
            st.success("● Master reachable", icon="✅")
            st.metric("Workers (Alive / Total)", f"{alive} / {workers}")
            st.metric("Total Cores", str(cores))
            st.metric("Cluster Memory",  f"{mem_gb} GB")
        except Exception as e:
            st.warning(f"Spark master UI not reachable: {e}")
            st.caption("(Spark may be running in local mode)")

    # ── Integration log ────────────────────────────────────────────────
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("<div class='section-header'>📋 Latest Integration Run Log</div>", unsafe_allow_html=True)
    log_docs = _get_collection("integration_log")
    if log_docs:
        log = log_docs[-1]
        log.pop("_id", None)
        c_l, c_r = st.columns(2)
        with c_l:
            st.json({k: v for k, v in log.items() if k.endswith("_docs")})
        with c_r:
            st.json({k: v for k, v in log.items() if not k.endswith("_docs")})
    else:
        st.info("No integration log found. Run `spark/jobs/integrate_results.py` first.")


# ===========================================================================
# Main router
# ===========================================================================

def main():
    page = _sidebar()

    if page == "🏠 Overview & KPIs":
        page_overview()
    elif page == "📊 Threat Analytics":
        page_threat_analytics()
    elif page == "🌐 IP Threat Intelligence":
        page_ip_intelligence()
    elif page == "🤖 ML Predictions":
        page_ml_predictions()
    elif page == "🖥️ Cluster Health":
        page_cluster_health()


if __name__ == "__main__":
    main()
