The **AI Threat Detection System** is a cybersecurity-focused machine learning application that detects network threats in **real-time** and from **static datasets**.
It uses **machine learning models** trained on network traffic features to classify whether a packet/flow is **normal** or **malicious**.

This project integrates:

* **Static Data Analysis** (offline datasets)
* **Real-Time Packet Capture** using `scapy`
* **Streamlit Interactive Dashboard** for visualization
* **IP Geolocation & Heatmaps** for threat tracking
* **Top 5 Suspicious IPs with Confidence Scores**
* **Live Alerts Feed**

---

### **2. About the Model**

* **Algorithm Used**: `RandomForestClassifier` (from Scikit-learn)

* **Why Random Forest?**

  * Handles high-dimensional datasets well
  * Resistant to overfitting
  * Works with both numerical & categorical features
  * Provides feature importance for analysis

* **Model Output:**

  * Binary Classification: `THREAT` or `SAFE`
  * Confidence scores (probability-based output)

---

### **3. Dataset Details**

* **Source**: Can be any structured intrusion detection dataset such as:

  * [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
  * [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html)

* **Size**: 2M+ rows (depending on dataset used)

* **Features**: **41 network features**, including:

  * `duration`, `protocol_type`, `service`, `flag`
  * `src_bytes`, `dst_bytes`
  * `count`, `srv_count`
  * Statistical traffic patterns
  * Connection state features

* **Target Variable**:

  * `0` → Safe traffic
  * `1` → Threat traffic

---

### **4. Training Process**

1. **Data Preprocessing**

   * Encoded categorical features (`protocol_type`, `service`, `flag`) using `LabelEncoder`
   * Scaled numerical features with `StandardScaler`
   * Removed irrelevant columns (e.g., timestamps, connection IDs)

2. **Train-Test Split**

   * `80%` training
   * `20%` testing

3. **Model Training**

   ```python
   from sklearn.ensemble import RandomForestClassifier
   model = RandomForestClassifier(n_estimators=100, random_state=42)
   model.fit(X_train, y_train)
   ```

4. **Evaluation**

   * Achieved **99–100% accuracy** on test set
   * High precision and recall for threat detection

---

### **5. Features Implemented**

✅ Threat detection from static datasets
✅ Real-time network packet capture (`scapy`)
✅ Real-time packet classification
✅ Source IP geolocation (`GeoLite2 Database` or IP API)
✅ IP-based heatmaps
✅ Alerts feed for suspicious activity
✅ Top 5 suspicious IPs table with confidence scores

---

### **6. Real-Time Threat Monitoring**

* Uses **Scapy** to capture live network traffic
* Extracts packet features such as:

  * Protocol
  * Source/Destination IP
  * Source/Destination Port
  * Packet length
* Applies same preprocessing pipeline as training data
* Classifies packets instantly using trained model
* Updates Streamlit dashboard **in real-time**

# Ai-Threat-detection-system
Ai Threat Detection System 
