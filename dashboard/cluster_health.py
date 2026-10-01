"""
Cluster Status & Health Monitor — Phase 11 (Dashboard sub-module)
Distributed Cyber Threat Intelligence Platform

Renders detailed cluster health status for:
  - MongoDB sharded cluster (router + shards)
  - Hadoop HDFS (NameNode + DataNodes)
  - Apache Spark (Master + Workers)
  - Integration pipeline audit log

Imported by dashboard/app.py for the "🖥️ Cluster Health" page.
Can also be run standalone:
    streamlit run dashboard/cluster_health.py
"""

import sys
import subprocess
from pathlib import Path
from datetime import datetime

import streamlit as st

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import MONGO_CONFIG, SPARK_CONFIG, HDFS_CONFIG, get_mongo_client


# ---------------------------------------------------------------------------
# Helper: coloured status badge
# ---------------------------------------------------------------------------

def _status_badge(ok: bool, ok_label: str = "Online", fail_label: str = "Offline") -> str:
    if ok:
        return f"<span style='color:#34d399; font-weight:600;'>● {ok_label}</span>"
    return f"<span style='color:#f87171; font-weight:600;'>✗ {fail_label}</span>"


def _section(title: str):
    st.markdown(
        f"<div style='font-size:1rem; font-weight:600; color:#7dd3fc; "
        f"border-left:3px solid #0ea5e9; padding-left:0.7rem; "
        f"margin:1.4rem 0 0.6rem;'>{title}</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# MongoDB health check
# ---------------------------------------------------------------------------

def _render_mongodb():
    _section("🍃 MongoDB Sharded Cluster")
    cols = st.columns(3)

    # Router (mongos)
    with cols[0]:
        st.markdown("**Router (mongos :27017)**")
        try:
            client = get_mongo_client(timeout_ms=6_000)
            status = client.admin.command("serverStatus")
            uptime = round(status.get("uptime", 0) / 3600, 1)
            conns  = status.get("connections", {}).get("current", "N/A")
            st.markdown(_status_badge(True, "Connected"), unsafe_allow_html=True)
            st.metric("Uptime",       f"{uptime} h")
            st.metric("Active Conns", str(conns))
            client.close()
        except Exception as exc:
            st.markdown(_status_badge(False), unsafe_allow_html=True)
            st.caption(str(exc)[:200])

    # Shard 1
    with cols[1]:
        st.markdown(f"**Shard 1 (:{MONGO_CONFIG['shard1_port']})**")
        try:
            from config.settings import get_mongo_client as gmc
            c = gmc(
                custom_uri=f"mongodb://{MONGO_CONFIG['host']}:{MONGO_CONFIG['shard1_port']}",
                timeout_ms=5_000,
            )
            c.admin.command("ping")
            st.markdown(_status_badge(True, "Reachable"), unsafe_allow_html=True)
            c.close()
        except Exception as exc:
            st.markdown(_status_badge(False), unsafe_allow_html=True)
            st.caption(str(exc)[:160])

    # Shard 2
    with cols[2]:
        st.markdown(f"**Shard 2 (:{MONGO_CONFIG['shard2_port']})**")
        try:
            from config.settings import get_mongo_client as gmc
            c = gmc(
                custom_uri=f"mongodb://{MONGO_CONFIG['host']}:{MONGO_CONFIG['shard2_port']}",
                timeout_ms=5_000,
            )
            c.admin.command("ping")
            st.markdown(_status_badge(True, "Reachable"), unsafe_allow_html=True)
            c.close()
        except Exception as exc:
            st.markdown(_status_badge(False), unsafe_allow_html=True)
            st.caption(str(exc)[:160])

    # Collection document counts
    _section("MongoDB Collection Document Counts")
    try:
        client  = get_mongo_client(timeout_ms=6_000)
        db      = client[MONGO_CONFIG["db_name"]]
        colls   = db.list_collection_names()
        counts  = {c: db[c].count_documents({}) for c in sorted(colls)}
        client.close()

        import pandas as pd
        df = pd.DataFrame(list(counts.items()), columns=["Collection", "Documents"])
        st.dataframe(df, use_container_width=True, hide_index=True)
    except Exception as exc:
        st.warning(f"Could not retrieve collection stats: {exc}")


# ---------------------------------------------------------------------------
# Hadoop HDFS health check
# ---------------------------------------------------------------------------

def _render_hadoop():
    _section("🐘 Hadoop HDFS Cluster")

    try:
        result = subprocess.run(
            ["hdfs", "dfsadmin", "-report"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            st.warning(f"HDFS returned exit code {result.returncode}.")
            st.code(result.stderr[:500], language="bash")
            return

        output = result.stdout
        lines  = output.split("\n")

        # Parse summary lines
        summary = {}
        for line in lines:
            for key in ["Configured Capacity", "DFS Used", "DFS Remaining",
                        "DFS Used%", "Live datanodes", "Dead datanodes"]:
                if line.strip().startswith(key + ":"):
                    summary[key] = line.split(":", 1)[1].strip()

        col1, col2, col3 = st.columns(3)
        col1.markdown(_status_badge(True, "NameNode Live"), unsafe_allow_html=True)
        col1.metric("Live DataNodes", summary.get("Live datanodes", "N/A"))
        col2.metric("Dead DataNodes",   summary.get("Dead datanodes", "N/A"))
        col2.metric("Configured Capacity", summary.get("Configured Capacity", "N/A"))
        col3.metric("DFS Used",          summary.get("DFS Used",      "N/A"))
        col3.metric("DFS Remaining",     summary.get("DFS Remaining", "N/A"))

        with st.expander("📋 Full HDFS dfsadmin -report output"):
            st.code(output, language="bash")

    except FileNotFoundError:
        st.warning("⚠ `hdfs` command not found on PATH. Hadoop may not be installed locally.")
        st.caption(f"Expected NameNode: {HDFS_CONFIG['namenode_host']}:{HDFS_CONFIG['namenode_port']}")
    except subprocess.TimeoutExpired:
        st.error("HDFS report timed out (>15s). Cluster may be unreachable.", icon="🔴")
    except Exception as exc:
        st.error(f"HDFS check failed: {exc}", icon="🔴")


# ---------------------------------------------------------------------------
# Apache Spark health check
# ---------------------------------------------------------------------------

def _render_spark():
    _section("⚡ Apache Spark Cluster")

    master_host = SPARK_CONFIG["master_host"]
    master_port = SPARK_CONFIG["master_port"]
    ui_url      = f"http://{master_host}:8080"

    try:
        import requests as req
        resp = req.get(f"{ui_url}/json/", timeout=6)
        resp.raise_for_status()
        data = resp.json()

        workers   = data.get("workers", [])
        alive     = [w for w in workers if w.get("state") == "ALIVE"]
        dead      = [w for w in workers if w.get("state") != "ALIVE"]
        cores     = data.get("cores", 0)
        mem_mb    = data.get("memory", 0)
        apps_run  = data.get("completedapps", [])

        col1, col2, col3, col4 = st.columns(4)
        col1.markdown(_status_badge(True, "Master Live"), unsafe_allow_html=True)
        col1.metric("Alive Workers",    str(len(alive)))
        col2.metric("Dead Workers",     str(len(dead)))
        col2.metric("Total Cores",      str(cores))
        col3.metric("Cluster Memory",   f"{round(mem_mb/1024,1)} GB")
        col3.metric("Completed Apps",   str(len(apps_run)))
        col4.caption(f"Spark UI: [{ui_url}]({ui_url})")
        col4.caption(f"Spark Master: spark://{master_host}:{master_port}")

        if workers:
            import pandas as pd
            wdf = pd.DataFrame([
                {
                    "Worker":  w.get("webuiaddress", w.get("id", "N/A")),
                    "State":   w.get("state", "N/A"),
                    "Cores":   w.get("cores", 0),
                    "Memory":  f"{round(w.get('memory',0)/1024,1)} GB",
                }
                for w in workers
            ])
            _section("Spark Worker Details")
            st.dataframe(wdf, use_container_width=True, hide_index=True)

    except Exception as exc:
        st.warning(
            f"Spark Master UI at `{ui_url}` not reachable ({exc}). "
            "Spark may be running in `local[*]` mode."
        )
        st.caption(f"Configured master: spark://{master_host}:{master_port}")


# ---------------------------------------------------------------------------
# Integration pipeline audit log
# ---------------------------------------------------------------------------

def _render_integration_log():
    _section("📋 Phase 10 Integration Pipeline — Audit Log")

    try:
        client = get_mongo_client(timeout_ms=6_000)
        db     = client[MONGO_CONFIG["db_name"]]
        docs   = list(db["integration_log"].find({}, {"_id": 0}).sort("integrated_at", -1).limit(5))
        client.close()
    except Exception:
        docs = []

    if not docs:
        st.info(
            "No integration log found. Run `python spark/jobs/integrate_results.py` "
            "to populate MongoDB from Spark pipeline outputs."
        )
        return

    latest = docs[0]

    # KPI row
    doc_cols = {k: v for k, v in latest.items() if k.endswith("_docs")}
    total_docs = sum(doc_cols.values())

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Documents Integrated",  f"{total_docs:,}")
    c2.metric("Integration Timestamp",       latest.get("integrated_at", "N/A")[:19])
    c3.metric("Pipeline Version",            latest.get("pipeline_version", "N/A").upper())

    # Per-collection counts
    if doc_cols:
        import pandas as pd
        df = pd.DataFrame(
            [{"Collection": k.replace("_docs","").replace("_"," ").title(), "Documents": v}
             for k, v in doc_cols.items()]
        ).sort_values("Documents", ascending=False)
        st.dataframe(df, use_container_width=True, hide_index=True)

    # Recent runs
    if len(docs) > 1:
        with st.expander(f"🕐 Previous {len(docs)-1} integration run(s)"):
            for doc in docs[1:]:
                st.markdown(
                    f"- **{doc.get('integrated_at','?')[:19]}** — "
                    f"Pipeline: `{doc.get('pipeline_version','?')}` — "
                    f"Time: {doc.get('execution_time_s','?')}s"
                )


# ---------------------------------------------------------------------------
# Main render function (called from app.py)
# ---------------------------------------------------------------------------

def render_cluster_health():
    st.markdown("## 🖥️ Cluster Status & Health")
    st.markdown(
        "<p style='color:#64748b; margin-bottom:1rem;'>"
        "Live diagnostic view of all distributed infrastructure components."
        "</p>",
        unsafe_allow_html=True,
    )

    _render_mongodb()
    st.markdown("<hr style='border-color:#1e293b;'>", unsafe_allow_html=True)
    _render_hadoop()
    st.markdown("<hr style='border-color:#1e293b;'>", unsafe_allow_html=True)
    _render_spark()
    st.markdown("<hr style='border-color:#1e293b;'>", unsafe_allow_html=True)
    _render_integration_log()


# ---------------------------------------------------------------------------
# Standalone entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    st.set_page_config(
        page_title="Cluster Health | CyberShield",
        page_icon="🖥️",
        layout="wide",
    )
    render_cluster_health()
