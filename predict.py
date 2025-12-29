import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import StandardScaler
import os

# ========== Load Model ==========
with open("models/threat_model.pkl", "rb") as f:
    model = pickle.load(f)

# ========== Load Encoders ==========
with open("models/encoders.pkl", "rb") as f:
    encoders = pickle.load(f)

# ========== Load New Data ==========
data_path = "data/new_data.csv"
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent',
    'hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate',
    'srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate'
]
df = pd.read_csv(data_path, header=None, names=columns)

# ========== Encode Categorical Columns ==========
for col, le in encoders.items():
    df[col] = df[col].map(lambda s: s if s in le.classes_ else '<unknown>')
    le.classes_ = np.append(le.classes_, '<unknown>')
    df[col] = le.transform(df[col])

# ========== Normalize ==========
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df)

# ========== Predict ==========
predictions = model.predict(df_scaled)

# ========== Output ==========
for i, pred in enumerate(predictions):
    label = "THREAT" if pred == 1 else "NORMAL"
    print(f"Row {i+1}: {label}")
