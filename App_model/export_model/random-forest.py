import pandas as pd
import numpy as np
import pickle

from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

RANDOM_STATE_SEED = 12

# Load và chọn các cột cần thiết
df_dataset = pd.read_csv(r"../export_model/necessary_data.csv")
selected_columns = ['Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'Label']
df_dataset = df_dataset[selected_columns]

# Xử lý dữ liệu: thay thế giá trị vô cực và bỏ các giá trị thiếu, chuyển nhãn
df_dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
df_dataset.dropna(inplace=True)
df_dataset.replace({"FTP-BruteForce": "Malicious", "SSH-Bruteforce": "Malicious"}, inplace=True)

# In ra số lượng mẫu mỗi loại trước khi cân bằng
print("Số lượng mẫu mỗi loại trước cân bằng:")
print(df_dataset['Label'].value_counts())
print()

# Cân bằng số mẫu giữa các lớp: undersampling theo số lượng mẫu của lớp ít nhất
min_count = df_dataset['Label'].value_counts().min()
df_equal = (
    df_dataset.groupby('Label')
    .apply(lambda x: x.sample(min_count, random_state=RANDOM_STATE_SEED))
    .reset_index(drop=True)
)

# In ra số lượng mẫu mỗi loại sau khi cân bằng
print("Số lượng mẫu mỗi loại sau cân bằng:")
print(df_equal['Label'].value_counts())
print()

# Chuyển đổi nhãn: Benign -> 0, Malicious -> 1
df_equal.replace({"Benign": 0, "Malicious": 1}, inplace=True)

# Tách dữ liệu thành train và test
train, test = train_test_split(df_equal, test_size=0.3, random_state=RANDOM_STATE_SEED)

# In ra số lượng mẫu của tập train và test
print("Số lượng mẫu trong tập train:", len(train))
print("Số lượng mẫu trong tập test:", len(test))
print()

# Chuẩn hóa dữ liệu với MinMaxScaler
min_max_scaler = MinMaxScaler().fit(train[selected_columns])
train[selected_columns] = min_max_scaler.transform(train[selected_columns])
test[selected_columns] = min_max_scaler.transform(test[selected_columns])

# Chuẩn bị dữ liệu cho mô hình
y_train = np.array(train.pop("Label"))
X_train = train.values
y_test = np.array(test.pop("Label"))
X_test = test.values

# Định nghĩa mô hình RandomForest và GridSearchCV
model = RandomForestClassifier(random_state=RANDOM_STATE_SEED)
hyperparameters = {'n_estimators': [50, 75, 100, 125, 150]}

clf = GridSearchCV(
    estimator=model,
    param_grid=hyperparameters,
    cv=5,
    verbose=1,
    n_jobs=-1
)

# Huấn luyện mô hình
clf.fit(X_train, y_train)

# Dự đoán trên tập test và đo độ chính xác
predictions = clf.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print("Test Accuracy:", accuracy)
print("\nClassification Report:")
print(classification_report(y_test, predictions))

# Tính và in ma trận nhầm lẫn dạng text trên terminal
cf_matrix = confusion_matrix(y_test, predictions)
print("Confusion Matrix:")
print(cf_matrix)

# Lưu mô hình tốt nhất vào file pickle
with open('../models/model-random-forest.pkl', 'wb') as file:
    pickle.dump(clf.best_estimator_, file)
print("Model saved successfully as '../models/model-random-forest.pkl'")
