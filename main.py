import pandas as pd
import numpy as np
import os
import pickle
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# ========== Step 1: File Paths ==========
train_path = "data/KDDTrain+.txt"
test_path = "data/KDDTest+.txt"

if not os.path.exists(train_path) or not os.path.exists(test_path):
    raise FileNotFoundError("Dataset files not found in 'data/' folder.")

# ========== Step 2: Define Column Names ==========
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent',
    'hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate',
    'srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','label'
]

# ========== Step 3: Load Dataset ==========
df_train = pd.read_csv(train_path, header=None, names=columns)
df_test = pd.read_csv(test_path, header=None, names=columns)

# ========== Step 4: Encode All Object Columns ==========
def safe_label_encode(train_df, test_df):
    for col in train_df.columns:
        if train_df[col].dtype == 'object' and col != 'label':
            le = LabelEncoder()
            train_df[col] = le.fit_transform(train_df[col])
            test_df[col] = test_df[col].map(lambda s: '<unknown>' if s not in le.classes_ else s)
            le.classes_ = np.append(le.classes_, '<unknown>')
            test_df[col] = le.transform(test_df[col])
    return train_df, test_df

df_train, df_test = safe_label_encode(df_train, df_test)

# ========== Step 5: Convert Labels to Binary ==========
df_train['label'] = df_train['label'].apply(lambda x: 0 if x == 'normal' else 1)
df_test['label'] = df_test['label'].apply(lambda x: 0 if x == 'normal' else 1)

# ========== Step 6: Split Features and Labels ==========
X_train = df_train.drop('label', axis=1)
y_train = df_train['label']
X_test = df_test.drop('label', axis=1)
y_test = df_test['label']

# ========== Debug: Check for Non-Numeric Values ==========
if X_train.select_dtypes(include='object').shape[1] > 0:
    raise ValueError("Non-numeric columns detected after encoding.")

# ========== Step 7: Normalize Features ==========
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# ========== Step 8: Train Model ==========
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ========== Step 9: Evaluate Model ==========
y_pred = model.predict(X_test)
print("✅ Model trained successfully!\n")
print("🧾 Classification Report:")
print(classification_report(y_test, y_pred))

# ========== Step 10: Save Model ==========
os.makedirs('models', exist_ok=True)
with open('models/threat_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("\n✅ Model saved to 'models/threat_model.pkl'")
# Encode all object (categorical) columns and save encoders
categorical_cols = ['protocol_type', 'service', 'flag']
encoders = {}

for col in categorical_cols:
    le = LabelEncoder()
    df_train[col] = le.fit_transform(df_train[col])
    df_test[col] = df_test[col].map(lambda s: s if s in le.classes_ else '<unknown>')
    le.classes_ = np.append(le.classes_, '<unknown>')
    df_test[col] = le.transform(df_test[col])
    encoders[col] = le

# Save encoders to use during prediction
import pickle
os.makedirs('models', exist_ok=True)
with open('models/encoders.pkl', 'wb') as f:
    pickle.dump(encoders, f)

print("✅ Encoders saved to 'models/encoders.pkl'")
