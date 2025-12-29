import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from live_capture import capture_packets
from geo_lookup import get_country_by_ip

# Load trained model and encoders
model = joblib.load("model/random_forest_model.pkl")
label_encoders = joblib.load("model/label_encoders.pkl")

# Preprocessing function
def preprocess(df):
    df = df.copy()
    for col, le in label_encoders.items():
        if col in df.columns:
            df[col] = le.transform(df[col].astype(str).fillna("Unknown"))
    return df

# Predict threat type
def predict_threat(df):
    processed = preprocess(df)
    predictions = model.predict(processed)
    prediction_probs = model.predict_proba(processed)
    df['threat_type'] = predictions
    df['confidence'] = prediction_probs.max(axis=1)
    return df

# Display source IP heatmap
def show_heatmap(df):
    df['country'] = df['src_ip'].apply(get_country_by_ip)
    country_counts = df['country'].value_counts().head(10)
    st.subheader("🌍 Top 10 Source Countries (Heatmap)")
    fig, ax = plt.subplots()
    sns.barplot(x=country_counts.values, y=country_counts.index, ax=ax, palette="mako")
    ax.set_xlabel("Packet Count")
    ax.set_ylabel("Country")
    st.pyplot(fig)

# Display real-time alert feed
def show_alert_feed(df):
    st.subheader("🚨 Real-Time Alert Feed")
    for index, row in df.iterrows():
        st.markdown(f"- **Threat Detected:** `{row['threat_type']}` from `{row['src_ip']}` to `{row['dst_ip']}` | Confidence: `{row['confidence']:.2f}`")

# Display top 5 suspicious IPs
def show_top_ips(df):
    st.subheader("⚠️ Top 5 Suspicious Source IPs")
    top_ips = df.groupby('src_ip')['confidence'].max().sort_values(ascending=False).head(5)
    st.table(top_ips.reset_index().rename(columns={'confidence': 'Max Confidence'}))

# Streamlit UI
st.set_page_config(page_title="AI Threat Detection Dashboard", layout="wide")
st.title("🔐 AI-Based Real-Time Threat Detection System")

if st.button("⚡ Start Live Detection"):
    live_df = capture_packets(packet_count=500)
    
    if not live_df.empty:
        result_df = predict_threat(live_df)

        col1, col2 = st.columns(2)
        with col1:
            show_heatmap(result_df)
        with col2:
            show_top_ips(result_df)

        show_alert_feed(result_df)

        st.success("✅ Live Detection Completed")
    else:
        st.warning("⚠️ No valid packets captured.")
