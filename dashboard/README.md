# Cyber Threat Intelligence Dashboard

Interactive Streamlit web application providing real-time security KPIs, threat distribution charts, IP reputation drill-downs, and distributed cluster monitoring.

## Responsibilities (Lead: Member 3)
- Phase 11: Streamlit frontend connected directly to MongoDB aggregations.

## Views & Pages
1. **Overview & Security KPIs**:
   - Total network events analyzed
   - Total attacks detected & threat percentage
   - Most active attack vector
   - Critical risk IP counter
2. **Threat Analytics**:
   - Attack breakdown donut/pie charts
   - Intrusion timeline (attacks over time)
   - Protocol distribution (TCP, UDP, ICMP)
3. **IP Threat Intelligence**:
   - Top attacking IPs table with risk scores (0-100)
   - Filter by severity (Critical, High, Medium, Low)
4. **ML Intrusion Predictions**:
   - Comparison between actual vs predicted attacks
   - Model confidence metrics
5. **Cluster Status & Health**:
   - MongoDB Shard status (`sh.status()`)
   - HDFS DataNodes and block health (`hdfs dfsadmin -report`)
   - Spark Master and Workers status
