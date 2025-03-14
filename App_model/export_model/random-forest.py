import pandas as pd
import numpy as np
import pickle
import time

from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    roc_auc_score, roc_curve, f1_score
)

RANDOM_STATE_SEED = 12

# 1. Tải và tiền xử lý dữ liệu
print("=== GIAI ĐOẠN 1: TẢI VÀ TIỀN XỬ LÝ DỮ LIỆU ===")
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

# 2. Cân bằng dữ liệu
print("=== GIAI ĐOẠN 2: CÂN BẰNG DỮ LIỆU ===")
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

# 3. Tách dữ liệu và chuẩn hóa
print("=== GIAI ĐOẠN 3: TÁCH DỮ LIỆU VÀ CHUẨN HÓA ===")
# Tách dữ liệu thành train và test
train, test = train_test_split(df_equal, test_size=0.3, random_state=RANDOM_STATE_SEED)

# In ra số lượng mẫu của tập train và test
print("Số lượng mẫu trong tập train:", len(train))
print("Số lượng mẫu trong tập test:", len(test))
print()

# Chuẩn hóa dữ liệu với MinMaxScaler
features = [col for col in selected_columns if col != 'Label']
min_max_scaler = MinMaxScaler().fit(train[features])

# Áp dụng scaler vào tập train và test
train_scaled = pd.DataFrame(
    min_max_scaler.transform(train[features]),
    columns=features
)
test_scaled = pd.DataFrame(
    min_max_scaler.transform(test[features]),
    columns=features
)

# Chuẩn bị dữ liệu cho mô hình
y_train = np.array(train['Label'])
X_train = train_scaled.values
y_test = np.array(test['Label'])
X_test = test_scaled.values

# 4. Định nghĩa và huấn luyện mô hình
print("=== GIAI ĐOẠN 4: HUẤN LUYỆN MÔ HÌNH ===")
model = RandomForestClassifier(random_state=RANDOM_STATE_SEED)
hyperparameters = {'n_estimators': [50, 75, 100, 125, 150]}

clf = GridSearchCV(
    estimator=model,
    param_grid=hyperparameters,
    cv=5,
    verbose=1,
    n_jobs=-1
)

# Đo thời gian huấn luyện
start_time = time.time()
clf.fit(X_train, y_train)
training_time = time.time() - start_time
print("Thời gian huấn luyện: {:.2f} giây".format(training_time))
print()

# In ra thông số tốt nhất từ GridSearchCV
print("Best Parameters:", clf.best_params_)
print("Best CV Score:", clf.best_score_)
print()

# 5. Đánh giá mô hình
print("=== GIAI ĐOẠN 5: ĐÁNH GIÁ MÔ HÌNH ===")
# Dự đoán và tính toán các chỉ số đánh giá
predictions = clf.predict(X_test)
probabilities = clf.predict_proba(X_test)[:, 1]

# Tính các chỉ số đánh giá
accuracy = accuracy_score(y_test, predictions)
roc_auc = roc_auc_score(y_test, probabilities)
f1 = f1_score(y_test, predictions)

# In kết quả đánh giá
print("Test Accuracy:", accuracy)
print("ROC AUC Score:", roc_auc)
print("F1 Score:", f1)
print()

# In chi tiết báo cáo phân loại và ma trận nhầm lẫn
print("Classification Report:")
print(classification_report(y_test, predictions))
print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))
print()

# Tính toán và in đường cong ROC (FPR, TPR, thresholds)
fpr, tpr, thresholds = roc_curve(y_test, probabilities)
print("ROC Curve:")
print("FPR:", fpr)
print("TPR:", tpr)
print("Thresholds:", thresholds)
print()

# Hiển thị feature importance (cho RandomForest)
importances = clf.best_estimator_.feature_importances_
feature_names = features
print("Feature Importances:")
for name, imp in zip(feature_names, importances):
    print(f"{name}: {imp:.4f}")
print()

# In kết quả chi tiết của GridSearchCV
cv_results = pd.DataFrame(clf.cv_results_)
print("GridSearchCV Detailed Results:")
print(cv_results[['params', 'mean_test_score', 'std_test_score', 'rank_test_score']])

# 6. Lưu mô hình
print("=== GIAI ĐOẠN 6: LƯU MÔ HÌNH ===")
# Lưu mô hình tốt nhất vào file pickle
with open('../models/model-random-forest.pkl', 'wb') as file:
    pickle.dump(clf.best_estimator_, file)
print("Model saved successfully as '../models/model-random-forest.pkl'")