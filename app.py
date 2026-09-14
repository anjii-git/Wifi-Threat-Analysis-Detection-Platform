import os
import tempfile
from collections import Counter, defaultdict

import streamlit as st
import pandas as pd
import plotly.express as px

from scapy.all import rdpcap, ARP, IP, TCP, UDP, ICMP
from scapy.layers.dot11 import Dot11


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Wi-Fi Security Threat Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main {
        background-color: #f7f9fc;
    }

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    .dashboard-title {
        font-size: 34px;
        font-weight: 800;
        margin-bottom: 5px;
    }

    .dashboard-subtitle {
        font-size: 16px;
        color: #64748b;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 23px;
        font-weight: 750;
        margin-top: 15px;
        margin-bottom: 10px;
    }

    .security-card {
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #e2e8f0;
        background: white;
        box-shadow: 0 2px 8px rgba(15, 23, 42, 0.05);
    }

    .small-text {
        font-size: 13px;
        color: #64748b;
    }

    .risk-number {
        font-size: 42px;
        font-weight: 800;
    }

    .footer {
        text-align: center;
        color: #64748b;
        font-size: 13px;
        margin-top: 40px;
        padding: 20px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="dashboard-title">🛡️ Wi-Fi Security Threat Analyzer</div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="dashboard-subtitle">
    PCAP-based network security analysis, ARP anomaly detection,
    Wi-Fi security indicators and risk assessment platform.
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("⚙️ Analysis Control")

st.sidebar.markdown(
    """
    *Project:*  
    Wi-Fi Security Threat Analysis & Detection Platform

    *Analysis Engine:*  
    Python + Scapy

    *Dashboard:*  
    Streamlit + Plotly
    """
)

uploaded_file = st.sidebar.file_uploader(
    "📂 Upload PCAP / PCAPNG",
    type=["pcap", "pcapng", "cap"]
)

st.sidebar.markdown("---")

st.sidebar.info(
    """
    *Ethical Use*

    Analyze only PCAP files that you own,
    created in your lab, or are authorized to analyze.
    """
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_time(packet):
    """Return packet timestamp as float."""
    try:
        return float(packet.time)
    except Exception:
        return None


def get_packet_protocol(packet):
    """Identify the main protocol."""
    try:
        if packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(Dot11):
            if packet.haslayer("Dot11WEP"):
                return "802.11 / WEP"
            return "802.11 / Wi-Fi"
        elif packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(IP):
            return "IP"
        else:
            return "Other"
    except Exception:
        return "Other"


def get_source(packet):
    """Extract source address."""
    try:
        if packet.haslayer(ARP):
            return packet[ARP].psrc

        if packet.haslayer(IP):
            return packet[IP].src

        if packet.haslayer(Dot11):
            return packet[Dot11].addr2 or "Unknown"

    except Exception:
        pass

    return "Unknown"


def get_destination(packet):
    """Extract destination address."""
    try:
        if packet.haslayer(ARP):
            return packet[ARP].pdst

        if packet.haslayer(IP):
            return packet[IP].dst

        if packet.haslayer(Dot11):
            return packet[Dot11].addr1 or "Unknown"

    except Exception:
        pass

    return "Unknown"


def analyze_packets(packets):
    """Perform complete packet analysis."""

    total_packets = len(packets)

    arp_packets = []
    arp_requests = []
    arp_replies = []

    wifi_packets = []
    wep_packets = []

    packet_records = []

    sender_counter = Counter()
    target_counter = Counter()

    gratuitous_arp = 0

    timestamps = []

    for index, packet in enumerate(packets, start=1):

        timestamp = safe_time(packet)

        if timestamp is not None:
            timestamps.append(timestamp)

        protocol = get_packet_protocol(packet)
        source = get_source(packet)
        destination = get_destination(packet)

        packet_records.append(
            {
                "Packet No": index,
                "Protocol": protocol,
                "Source": source,
                "Destination": destination,
                "Length": len(packet),
            }
        )

        # ----------------------------------------------------
        # ARP
        # ----------------------------------------------------

        if packet.haslayer(ARP):

            arp_packets.append(packet)

            sender_counter[packet[ARP].psrc] += 1
            target_counter[packet[ARP].pdst] += 1

            if packet[ARP].op == 1:
                arp_requests.append(packet)

            elif packet[ARP].op == 2:
                arp_replies.append(packet)

            # Gratuitous ARP:
            # sender IP == target IP
            try:
                if packet[ARP].psrc == packet[ARP].pdst:
                    gratuitous_arp += 1
            except Exception:
                pass

        # ----------------------------------------------------
        # WI-FI / 802.11
        # ----------------------------------------------------

        if packet.haslayer(Dot11):

            wifi_packets.append(packet)

            if packet.haslayer("Dot11WEP"):
                wep_packets.append(packet)

    # --------------------------------------------------------
    # TIME ANALYSIS
    # --------------------------------------------------------

    duration = 0

    if len(timestamps) >= 2:
        duration = max(timestamps) - min(timestamps)

    if duration <= 0:
        duration = 1

    packets_per_second = total_packets / duration
    arp_per_second = len(arp_packets) / duration

    # --------------------------------------------------------
    # BURST ANALYSIS
    # --------------------------------------------------------

    second_counter = Counter()

    for packet in arp_packets:

        timestamp = safe_time(packet)

        if timestamp is not None:
            second_counter[int(timestamp)] += 1

    max_arp_burst = max(second_counter.values()) if second_counter else 0

    return {
        "total_packets": total_packets,
        "arp_packets": arp_packets,
        "arp_requests": arp_requests,
        "arp_replies": arp_replies,
        "wifi_packets": wifi_packets,
        "wep_packets": wep_packets,
        "packet_records": packet_records,
        "sender_counter": sender_counter,
        "target_counter": target_counter,
        "gratuitous_arp": gratuitous_arp,
        "duration": duration,
        "packets_per_second": packets_per_second,
        "arp_per_second": arp_per_second,
        "max_arp_burst": max_arp_burst,
    }


# ============================================================
# RISK ENGINE
# ============================================================

def calculate_risk(analysis):
    """
    Weighted rule-based risk engine.

    This score is an analytical indicator.
    It does NOT prove that an attack occurred.
    """

    score = 0
    indicators = []

    total = analysis["total_packets"]
    arp_count = len(analysis["arp_packets"])
    requests = len(analysis["arp_requests"])
    replies = len(analysis["arp_replies"])

    unique_senders = len(analysis["sender_counter"])
    unique_targets = len(analysis["target_counter"])

    gratuitous = analysis["gratuitous_arp"]
    max_burst = analysis["max_arp_burst"]

    # --------------------------------------------------------
    # 1. ARP VOLUME
    # --------------------------------------------------------

    if arp_count >= 500:
        score += 25
        indicators.append(
            ("High ARP volume", 25, "HIGH")
        )

    elif arp_count >= 200:
        score += 15
        indicators.append(
            ("Elevated ARP volume", 15, "MEDIUM")
        )

    elif arp_count >= 50:
        score += 8
        indicators.append(
            ("Moderate ARP activity", 8, "LOW")
        )

    # --------------------------------------------------------
    # 2. REQUEST RATIO
    # --------------------------------------------------------

    request_ratio = 0

    if arp_count > 0:
        request_ratio = (requests / arp_count) * 100

    if request_ratio >= 95:
        score += 20
        indicators.append(
            ("Very high ARP request ratio", 20, "HIGH")
        )

    elif request_ratio >= 80:
        score += 10
        indicators.append(
            ("High ARP request ratio", 10, "MEDIUM")
        )

    # --------------------------------------------------------
    # 3. REPEATED TARGET
    # --------------------------------------------------------

    max_target_requests = 0

    if analysis["target_counter"]:
        max_target_requests = max(
            analysis["target_counter"].values()
        )

    if max_target_requests >= 50:
        score += 15
        indicators.append(
            ("Repeated ARP target", 15, "HIGH")
        )

    elif max_target_requests >= 20:
        score += 8
        indicators.append(
            ("Repeated ARP target", 8, "MEDIUM")
        )

    # --------------------------------------------------------
    # 4. MULTIPLE SENDERS
    # --------------------------------------------------------

    if unique_senders >= 20:
        score += 15
        indicators.append(
            ("Large number of ARP senders", 15, "HIGH")
        )

    elif unique_senders >= 5:
        score += 8
        indicators.append(
            ("Multiple ARP senders", 8, "MEDIUM")
        )

    # --------------------------------------------------------
    # 5. ARP BURST
    # --------------------------------------------------------

    if max_burst >= 100:
        score += 15
        indicators.append(
            ("Extreme ARP burst", 15, "HIGH")
        )

    elif max_burst >= 50:
        score += 10
        indicators.append(
            ("High ARP burst", 10, "MEDIUM")
        )

    elif max_burst >= 20:
        score += 5
        indicators.append(
            ("ARP burst detected", 5, "LOW")
        )

    # --------------------------------------------------------
    # 6. GRATUITOUS ARP
    # --------------------------------------------------------

    if gratuitous >= 20:
        score += 10
        indicators.append(
            ("High gratuitous ARP activity", 10, "HIGH")
        )

    elif gratuitous >= 5:
        score += 5
        indicators.append(
            ("Gratuitous ARP observed", 5, "MEDIUM")
        )

    # --------------------------------------------------------
    # 7. WEP CONTEXT
    # --------------------------------------------------------

    wep_count = len(analysis["wep_packets"])

    if wep_count > 0:
        score += 5
        indicators.append(
            ("WEP traffic observed", 5, "CONTEXT")
        )

    # Limit score
    score = min(score, 100)

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if score >= 80:
        level = "CRITICAL"

    elif score >= 60:
        level = "HIGH"

    elif score >= 30:
        level = "MEDIUM"

    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "indicators": indicators,
        "request_ratio": request_ratio,
        "max_target_requests": max_target_requests,
        "unique_senders": unique_senders,
        "unique_targets": unique_targets,
    }


# ============================================================
# LOAD PCAP
# ============================================================

if uploaded_file is None:

    st.info(
        "👈 Upload a PCAP or PCAPNG file from the sidebar to begin analysis."
    )

    st.markdown("## 🔍 What this platform analyzes")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            """
            ### 📡 Wi-Fi Traffic

            - 802.11 packets
            - WEP indicators
            - Wireless traffic statistics
            """
        )

    with col2:
        st.markdown(
            """
            ### 🔎 ARP Analysis

            - ARP requests
            - ARP replies
            - Repeated targets
            - Gratuitous ARP
            """
        )

    with col3:
        st.markdown(
            """
            ### 🛡️ Threat Detection

            - Risk scoring
            - Traffic bursts
            - Suspicious activity indicators
            - Security recommendations
            """
        )

    st.stop()


# ============================================================
# SAVE UPLOADED FILE TEMPORARILY
# ============================================================

try:

    file_extension = os.path.splitext(
        uploaded_file.name
    )[1]

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=file_extension
    ) as temp_file:

        temp_file.write(uploaded_file.getbuffer())
        temp_path = temp_file.name

    packets = rdpcap(temp_path)

    os.remove(temp_path)

except Exception as e:

    st.error(
        f"❌ Could not read the capture file: {e}"
    )

    st.stop()


# ============================================================
# ANALYZE
# ============================================================

analysis = analyze_packets(packets)

risk = calculate_risk(analysis)


# ============================================================
# FILE INFORMATION
# ============================================================

st.success(
    f"✅ Successfully loaded *{uploaded_file.name}*"
)

st.caption(
    f"Analysis duration: {analysis['duration']:.2f} seconds"
)


# ============================================================
# TOP SECURITY SUMMARY
# ============================================================

st.markdown(
    '<div class="section-title">🛡️ Security Overview</div>',
    unsafe_allow_html=True
)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        "Total Packets",
        f"{analysis['total_packets']:,}"
    )

with col2:
    st.metric(
        "ARP Packets",
        f"{len(analysis['arp_packets']):,}"
    )

with col3:
    st.metric(
        "Wi-Fi Packets",
        f"{len(analysis['wifi_packets']):,}"
    )

with col4:
    st.metric(
        "WEP Packets",
        f"{len(analysis['wep_packets']):,}"
    )

with col5:
    st.metric(
        "Risk Score",
        f"{risk['score']}/100"
    )


# ============================================================
# RISK STATUS
# ============================================================

st.markdown("---")

risk_col1, risk_col2 = st.columns([1, 2])

with risk_col1:

    st.markdown("### 🚨 Security Risk")

    st.markdown(
        f"""
        <div class="security-card">

        <div class="risk-number">
        {risk['score']}/100
        </div>

        <h2>{risk['level']}</h2>

        <div class="small-text">
        Weighted rule-based security assessment
        </div>

        </div>
        """,
        unsafe_allow_html=True
    )

with risk_col2:

    st.markdown("### 🧠 Assessment")

    if risk["level"] == "CRITICAL":

        st.error(
            "Critical activity indicators detected. "
            "Investigate the capture carefully."
        )

    elif risk["level"] == "HIGH":

        st.warning(
            "High network activity indicators detected. "
            "Repeated ARP or burst behaviour requires investigation."
        )

    elif risk["level"] == "MEDIUM":

        st.warning(
            "Moderate security indicators detected. "
            "Further packet-level investigation is recommended."
        )

    else:

        st.success(
            "No strong indicators were detected by the current "
            "rule-based detection engine."
        )

    st.caption(
        "Important: Risk score is an analytical indicator and "
        "does not by itself prove that an attack occurred."
    )


# ============================================================
# TABS
# ============================================================

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
    [
        "📊 Overview",
        "📡 Traffic Analysis",
        "🚨 Threat Detection",
        "🔎 Packet Explorer",
        "📚 Wi-Fi Security",
        "📋 Report"
    ]
)


# ============================================================
# TAB 1 - OVERVIEW
# ============================================================

with tab1:

    st.markdown("## 📊 Network Overview")

    arp_percentage = 0

    if analysis["total_packets"] > 0:
        arp_percentage = (
            len(analysis["arp_packets"])
            / analysis["total_packets"]
        ) * 100

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "ARP %",
            f"{arp_percentage:.2f}%"
        )

    with col2:
        st.metric(
            "ARP Requests",
            f"{len(analysis['arp_requests']):,}"
        )

    with col3:
        st.metric(
            "ARP Replies",
            f"{len(analysis['arp_replies']):,}"
        )

    with col4:
        st.metric(
            "Unique Senders",
            f"{risk['unique_senders']:,}"
        )

    st.markdown("### 📦 Protocol Distribution")

    protocol_counter = Counter(
        row["Protocol"]
        for row in analysis["packet_records"]
    )

    protocol_df = pd.DataFrame(
        {
            "Protocol": list(protocol_counter.keys()),
            "Packets": list(protocol_counter.values())
        }
    )

    if not protocol_df.empty:

        fig = px.pie(
            protocol_df,
            names="Protocol",
            values="Packets",
            hole=0.45,
            title="Protocol Distribution"
        )

        fig.update_layout(
            height=430
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )


# ============================================================
# TAB 2 - TRAFFIC ANALYSIS
# ============================================================

with tab2:

    st.markdown("## 📡 Traffic Analysis")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Packets / Second",
            f"{analysis['packets_per_second']:.2f}"
        )

    with col2:
        st.metric(
            "ARP / Second",
            f"{analysis['arp_per_second']:.2f}"
        )

    with col3:
        st.metric(
            "Maximum ARP Burst",
            f"{analysis['max_arp_burst']}"
        )

    st.markdown("### 👤 Top ARP Senders")

    sender_data = (
        analysis["sender_counter"]
        .most_common(10)
    )

    if sender_data:

        sender_df = pd.DataFrame(
            sender_data,
            columns=["Source IP", "ARP Packets"]
        )

        fig_sender = px.bar(
            sender_df,
            x="ARP Packets",
            y="Source IP",
            orientation="h",
            title="Top ARP Senders"
        )

        fig_sender.update_layout(
            height=450,
            yaxis={"categoryorder": "total ascending"}
        )

        st.plotly_chart(
            fig_sender,
            width="stretch"
        )

    else:

        st.info("No ARP sender data available.")


    st.markdown("### 🎯 Top Requested IP Addresses")

    target_data = (
        analysis["target_counter"]
        .most_common(10)
    )

    if target_data:

        target_df = pd.DataFrame(
            target_data,
            columns=["Target IP", "Requests"]
        )

        fig_target = px.bar(
            target_df,
            x="Target IP",
            y="Requests",
            title="Most Requested IP Addresses"
        )

        fig_target.update_layout(
            height=430
        )

        st.plotly_chart(
            fig_target,
            width="stretch"
        )

    else:

        st.info("No ARP target data available.")


# ============================================================
# TAB 3 - THREAT DETECTION
# ============================================================

with tab3:

    st.markdown("## 🚨 Threat Detection Engine")

    st.write(
        "The detection engine evaluates multiple network indicators "
        "instead of relying on a single threshold."
    )

    detection_rows = []

    for name, points, severity in risk["indicators"]:

        detection_rows.append(
            {
                "Detection Indicator": name,
                "Risk Points": points,
                "Severity": severity
            }
        )

    if detection_rows:

        detection_df = pd.DataFrame(
            detection_rows
        )

        st.dataframe(
            detection_df,
            width="stretch",
            hide_index=True
        )

    else:

        st.success(
            "No suspicious indicators were triggered."
        )


    st.markdown("### 🔬 Detection Metrics")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "ARP Request Ratio",
            f"{risk['request_ratio']:.2f}%"
        )

    with col2:

        st.metric(
            "Repeated Target",
            f"{risk['max_target_requests']}"
        )

    with col3:

        st.metric(
            "Gratuitous ARP",
            f"{analysis['gratuitous_arp']}"
        )


    st.markdown("### 🧩 Security Indicators")

    indicators = [
        (
            "ARP Volume",
            len(analysis["arp_packets"]),
            "Number of ARP packets detected"
        ),
        (
            "ARP Request Ratio",
            f"{risk['request_ratio']:.2f}%",
            "Percentage of ARP packets that are requests"
        ),
        (
            "Unique Senders",
            risk["unique_senders"],
            "Number of different ARP source addresses"
        ),
        (
            "Unique Targets",
            risk["unique_targets"],
            "Number of different requested IP addresses"
        ),
        (
            "Maximum ARP Burst",
            analysis["max_arp_burst"],
            "Highest ARP packet count observed within one second"
        ),
        (
            "Gratuitous ARP",
            analysis["gratuitous_arp"],
            "ARP packets where sender and target IP are the same"
        )
    ]

    indicator_df = pd.DataFrame(
        indicators,
        columns=[
            "Indicator",
            "Value",
            "Description"
        ]
    )

    st.dataframe(
        indicator_df,
        width="stretch",
        hide_index=True
    )


# ============================================================
# TAB 4 - PACKET EXPLORER
# ============================================================

with tab4:

    st.markdown("## 🔎 Packet Explorer")

    packet_df = pd.DataFrame(
        analysis["packet_records"]
    )

    if packet_df.empty:

        st.info("No packet records available.")

    else:

        search = st.text_input(
            "🔍 Search packets",
            placeholder="Search IP, MAC address or protocol..."
        )

        protocol_options = [
            "All"
        ] + sorted(
            packet_df["Protocol"].unique().tolist()
        )

        selected_protocol = st.selectbox(
            "Protocol filter",
            protocol_options
        )

        filtered_df = packet_df.copy()

        if selected_protocol != "All":

            filtered_df = filtered_df[
                filtered_df["Protocol"]
                == selected_protocol
            ]

        if search:

            search = search.lower()

            mask = (
                filtered_df.astype(str)
                .apply(
                    lambda row:
                    row.str.lower().str.contains(
                        search,
                        na=False
                    ).any(),
                    axis=1
                )
            )

            filtered_df = filtered_df[mask]

        st.caption(
            f"Showing {len(filtered_df):,} packets"
        )

        st.dataframe(
            filtered_df,
            width="stretch",
            height=500,
            hide_index=True
        )

        csv_data = filtered_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            label="⬇️ Download Packet Analysis CSV",
            data=csv_data,
            file_name="packet_analysis.csv",
            mime="text/csv"
        )


# ============================================================
# TAB 5 - WI-FI SECURITY
# ============================================================

with tab5:

    st.markdown("## 📚 Wi-Fi Security Analysis")

    st.markdown(
        """
        ### 🔐 WEP Security

        WEP (Wired Equivalent Privacy) is an older Wi-Fi security
        mechanism that is considered insecure by modern standards.

        This project uses PCAP analysis to identify whether
        wireless/WEP traffic is present in a capture.
        """
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "802.11 Packets",
            len(analysis["wifi_packets"])
        )

    with col2:

        st.metric(
            "WEP Packets",
            len(analysis["wep_packets"])
        )

    with col3:

        if len(analysis["wep_packets"]) > 0:
            st.warning("WEP observed")
        else:
            st.success("No WEP observed")


    st.markdown("### ☕ Caffe Latte Case Study")

    st.markdown(
        """
        *Caffe Latte* is a historical WEP-related attack concept
        involving weaknesses in WEP/ARP behaviour.

        In this project, Caffe Latte is treated as a
        *security research case study*.

        The presence of ARP traffic alone does *not* mean that
        a Caffe Latte attack occurred.

        A suitable authorized wireless capture containing
        relevant 802.11/WEP characteristics would be required
        for deeper case-study analysis.
        """
    )

    st.info(
        "Current ARP-focused PCAP analysis should be described as "
        "'ARP anomaly analysis', not as proof of a Caffe Latte attack."
    )


    st.markdown("### 🆚 Wi-Fi Security Comparison")

    comparison_df = pd.DataFrame(
        [
            [
                "WEP",
                "Legacy",
                "Weak",
                "Not recommended"
            ],
            [
                "WPA",
                "Legacy",
                "Better than WEP",
                "Avoid when possible"
            ],
            [
                "WPA2",
                "Modern",
                "Strong with AES",
                "Recommended"
            ],
            [
                "WPA3",
                "Modern",
                "Stronger",
                "Preferred where supported"
            ],
        ],
        columns=[
            "Security",
            "Generation",
            "General Strength",
            "Recommendation"
        ]
    )

    st.dataframe(
        comparison_df,
        width="stretch",
        hide_index=True
    )


# ============================================================
# TAB 6 - REPORT
# ============================================================

with tab6:

    st.markdown("## 📋 Security Analysis Report")

    st.markdown("### Executive Summary")

    report_text = f"""
*Capture File:* {uploaded_file.name}

*Total Packets:* {analysis['total_packets']:,}

*ARP Packets:* {len(analysis['arp_packets']):,}

*ARP Requests:* {len(analysis['arp_requests']):,}

*ARP Replies:* {len(analysis['arp_replies']):,}

*802.11/Wi-Fi Packets:* {len(analysis['wifi_packets']):,}

*WEP Packets:* {len(analysis['wep_packets']):,}

*Unique ARP Senders:* {risk['unique_senders']:,}

*Unique ARP Targets:* {risk['unique_targets']:,}

*Gratuitous ARP:* {analysis['gratuitous_arp']:,}

*Maximum ARP Burst:* {analysis['max_arp_burst']:,}

*Risk Score:* {risk['score']}/100

*Risk Level:* {risk['level']}
"""

    st.code(
        report_text,
        language="text"
    )


    st.markdown("### 🛠️ Recommended Actions")

    recommendations = []

    if len(analysis["arp_packets"]) >= 200:

        recommendations.append(
            "Investigate elevated ARP activity and identify the responsible hosts."
        )

    if risk["request_ratio"] >= 80:

        recommendations.append(
            "Review the high ARP request ratio for abnormal communication patterns."
        )

    if risk["max_target_requests"] >= 20:

        recommendations.append(
            "Investigate repeatedly targeted IP addresses."
        )

    if analysis["gratuitous_arp"] >= 5:

        recommendations.append(
            "Review gratuitous ARP traffic for possible address-resolution anomalies."
        )

    if len(analysis["wep_packets"]) > 0:

        recommendations.append(
            "Replace legacy WEP security with WPA2/WPA3 where possible."
        )

    if not recommendations:

        recommendations.append(
            "No major indicators were triggered by the current rule-based engine."
        )

    for recommendation in recommendations:

        st.write(
            f"• {recommendation}"
        )


    st.markdown("### ⚠️ Interpretation")

    st.warning(
        """
        This report is based on packet-level indicators and
        rule-based analysis. A high risk score should be treated
        as a reason for investigation, not as definitive proof
        of malicious activity.
        """
    )


# ============================================================
# PROJECT ARCHITECTURE
# ============================================================

st.markdown("---")

st.markdown(
    "## 🏗️ Project Architecture"
)

st.code(
    """
                    PCAP / PCAPNG
                          │
                          ▼
                    Python + Scapy
                          │
                          ▼
                  Packet Extraction
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
          ARP          Wi-Fi/WEP    Statistics
        Analysis        Analysis     Analysis
             │            │            │
             └────────────┼────────────┘
                          ▼
                    Threat Engine
                          │
                          ▼
                    Risk Score /100
                          │
                          ▼
                 Streamlit Dashboard
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
      Detection       Visualization      Report
    """,
    language="text"
)


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">
    🛡️ Wi-Fi Security Threat Analysis & Detection Platform
    <br>
    Built with Python • Scapy • Streamlit • Plotly
    <br><br>
    Educational and authorized security analysis only.
    </div>
    """,
    unsafe_allow_html=True
)