import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

# Set page configuration
st.set_page_config(
    page_title="Security Threat Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Set random seed for reproducibility
np.random.seed(42)

# ======================
# Data Generation Functions
# ======================


def generate_ransomware_data():
    timestamps = pd.date_range(start="2025-03-01", periods=2000, freq="min")

    normal_metrics = {
        "CPU_Usage": np.random.normal(25, 8, len(timestamps)),
        "Disk_Read": np.random.normal(15, 5, len(timestamps)),
        "Disk_Write": np.random.normal(8, 3, len(timestamps)),
        "Memory_Usage": np.random.normal(40, 5, len(timestamps)),
        "Network_Activity": np.random.normal(10, 3, len(timestamps))
    }

    attack_indices = np.random.choice(len(timestamps)-20, 80, replace=False)
    ransomware_metrics = {k: v.copy() for k, v in normal_metrics.items()}

    for idx in attack_indices:
        burst_length = np.random.randint(10, 20)
        ransomware_metrics["CPU_Usage"][idx:idx +
                                        burst_length] = np.random.uniform(85, 100, burst_length)
        ransomware_metrics["Disk_Read"][idx:idx +
                                        burst_length] = np.random.uniform(60, 120, burst_length)
        ransomware_metrics["Disk_Write"][idx:idx +
                                         burst_length] = np.random.uniform(70, 160, burst_length)
        ransomware_metrics["Memory_Usage"][idx:idx +
                                           burst_length] = np.random.uniform(70, 90, burst_length)
        ransomware_metrics["Network_Activity"][idx:idx +
                                               burst_length] = np.random.uniform(50, 200, burst_length)

    return pd.DataFrame({
        "Timestamp": timestamps,
        **ransomware_metrics,
        "Ransomware_Attack": [1 if i in attack_indices else 0 for i in range(len(timestamps))]
    })


def generate_phishing_data():
    timestamps = pd.date_range(start="2025-03-01", periods=2000, freq="min")
    normal_metrics = {
        "Clicks": np.random.normal(10, 3, len(timestamps)),
        "Time_Spent": np.random.normal(300, 50, len(timestamps)),
        "Mouse_Movements": np.random.normal(500, 100, len(timestamps)),
        "Typing_Speed": np.random.normal(40, 10, len(timestamps)),
        "Referral_Source": np.random.choice(["Direct", "Search Engine", "Social Media", "Email"], size=len(timestamps)),
        "Phishing_Attempt": 0
    }

    df = pd.DataFrame(normal_metrics)
    attack_indices = np.random.choice(len(df)-20, 80, replace=False)

    for idx in attack_indices:
        burst_length = np.random.randint(10, 20)
        burst_indices = list(range(idx, min(idx + burst_length, len(df))))
        df.loc[burst_indices, ["Clicks", "Time_Spent", "Mouse_Movements", "Typing_Speed"]] = np.random.uniform(
            low=[50, 30, 100, 10], high=[100, 100, 200, 20], size=(len(burst_indices), 4))
        df.loc[burst_indices, "Referral_Source"] = "Suspicious Link"
        df.loc[burst_indices, "Phishing_Attempt"] = 1

    df["Timestamp"] = timestamps
    return df


def generate_botnet_data():
    timestamps = pd.date_range(start="2025-03-01", periods=2000, freq="min")
    metrics = {
        "Botnet_Flow_Count": np.random.normal(30, 10, len(timestamps)),
        "Connection_Duration": np.random.normal(60, 20, len(timestamps)),
        "Inbound_Packets": np.random.normal(100, 30, len(timestamps)),
        "Outbound_Packets": np.random.normal(100, 30, len(timestamps)),
        "Unique_IPs": np.random.normal(10, 3, len(timestamps))
    }

    attack_indices = np.random.choice(len(timestamps)-20, 60, replace=False)
    for idx in attack_indices:
        burst_length = np.random.randint(10, 20)
        metrics["Botnet_Flow_Count"][idx:idx +
                                     burst_length] = np.random.uniform(150, 300, burst_length)
        metrics["Connection_Duration"][idx:idx +
                                       burst_length] = np.random.uniform(180, 300, burst_length)
        metrics["Inbound_Packets"][idx:idx +
                                   burst_length] = np.random.uniform(500, 1000, burst_length)
        metrics["Outbound_Packets"][idx:idx +
                                    burst_length] = np.random.uniform(500, 1000, burst_length)
        metrics["Unique_IPs"][idx:idx +
                              burst_length] = np.random.uniform(50, 100, burst_length)

    return pd.DataFrame({
        "Timestamp": timestamps,
        **metrics,
        "Botnet_Traffic": [1 if i in attack_indices else 0 for i in range(len(timestamps))]
    })

# ======================
# Visualization Functions
# ======================


def show_ransomware_analysis(df):
    filtered_df = df.copy()
    metrics = ["CPU_Usage", "Memory_Usage",
               "Disk_Read", "Disk_Write", "Network_Activity"]
    for metric in metrics:
        fig = px.line(filtered_df, x="Timestamp", y=metric,
                      title=f"{metric.replace('_', ' ')} Over Time")
        st.plotly_chart(fig, use_container_width=True)


def show_phishing_analysis(df):
    col1, col2 = st.columns(2)
    with col1:
        fig = px.scatter(df, x="Clicks", y="Time_Spent", color="Phishing_Attempt",
                         title="Clicks vs Time Spent", color_continuous_scale=["blue", "red"])
        st.plotly_chart(fig, use_container_width=True)

        fig = px.histogram(df, x="Typing_Speed", color="Phishing_Attempt",
                           title="Typing Speed Distribution", color_discrete_sequence=["blue", "red"])
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        fig = px.histogram(df, x="Referral_Source", color="Phishing_Attempt",
                           title="Referral Sources Distribution", color_discrete_sequence=["blue", "red"])
        st.plotly_chart(fig, use_container_width=True)

        fig = px.box(df, x="Phishing_Attempt", y="Mouse_Movements",
                     title="Mouse Movements Analysis", color_discrete_sequence=["blue", "red"])
        st.plotly_chart(fig, use_container_width=True)


def show_botnet_analysis(df):
    # st.subheader("📶 Botnet Traffic Analysis")
    metrics = ["Botnet_Flow_Count", "Connection_Duration",
               "Inbound_Packets", "Outbound_Packets", "Unique_IPs"]
    for metric in metrics:
        fig = px.line(df, x="Timestamp", y=metric, color="Botnet_Traffic",
                      title=f"{metric.replace('_', ' ')} Over Time")
        st.plotly_chart(fig, use_container_width=True)

# ======================
# Main Application
# ======================


def show_homepage():
    st.title("Cyber Deception & Detection: A Multi-Layer Security Analysis")

    st.markdown("""
    ## Comprehensive Threat Analysis Platform

    **Investigate sophisticated cyber threats through multi-layered security analytics**
    """)

    st.markdown("---")
    st.header("👥 Project Team")
    cols = st.columns(4)
    with cols[0]:
        st.markdown("**Saahil**  \n 22BCS105")
    with cols[1]:
        st.markdown("**Rohit**  \n 22BCS100")
    with cols[2]:
        st.markdown("**Shriya**  \n 22BCS121")
    with cols[3]:
        st.markdown("**Laxmi**  \n 22BCS059")

    st.markdown("---")
    st.header("🔍 Project Overview")
    st.markdown("""
    This interactive dashboard provides in-depth analysis of various cyber threats:
    
    - **Ransomware Detection**: System resource monitoring with attack pattern identification
    - **Phishing Analysis**: User behavior analytics and suspicious activity detection
    - **Network Security**: Traffic pattern analysis and anomaly detection
    - **Fraud Prevention**: Transaction monitoring and suspicious activity alerts
    """)

    st.markdown("---")
    st.header("📊 Analysis Methodology")
    cols = st.columns(3)
    with cols[0]:
        st.markdown(
            "### Data Collection  \nSynthetic data generation  \nReal-world dataset integration")
    with cols[1]:
        st.markdown(
            "### Threat Detection  \nMachine learning models  \nAnomaly detection algorithms")
    with cols[2]:
        st.markdown(
            "### Visualization  \nInteractive charts  \nReal-time monitoring")


def main():
    st.sidebar.title("Navigation")
    threat_type = st.sidebar.selectbox("Select Analysis Module", [
                                       "Home", "Ransomware", "Phishing", "Botnet"], index=0)

    if threat_type == "Home":
        show_homepage()
    elif threat_type == "Ransomware":
        st.header("🛡️ Ransomware Attack Analysis")
        data = generate_ransomware_data()
        show_ransomware_analysis(data)
    elif threat_type == "Phishing":
        st.header("🎣 Phishing Attempt Analysis")
        data = generate_phishing_data()
        show_phishing_analysis(data)
    elif threat_type == "Botnet":
        st.header("📶 Botnet Traffic Analysis")
        data = generate_botnet_data()
        show_botnet_analysis(data)


if __name__ == "__main__":
    main()
