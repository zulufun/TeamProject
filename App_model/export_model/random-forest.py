import pandas as pd
import numpy as np
import pickle
import time
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.colors import ListedColormap

from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    roc_auc_score, roc_curve, f1_score, precision_recall_curve, auc
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
pre_balance_counts = df_dataset['Label'].value_counts()
print(pre_balance_counts)
print()

# Tạo thư mục để lưu hình ảnh
import os
output_dir = "../visualizations"
os.makedirs(output_dir, exist_ok=True)

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
post_balance_counts = df_equal['Label'].value_counts()
print(post_balance_counts)
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

# Lưu kết quả Grid Search để hiển thị trong visualization sau này
cv_results = pd.DataFrame(clf.cv_results_)
best_n_estimators = clf.best_params_['n_estimators']
best_cv_score = clf.best_score_

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

# In chi tiết báo cáo phân loại
print("Classification Report:")
report = classification_report(y_test, predictions)
print(report)

# Tính toán ma trận nhầm lẫn
cm = confusion_matrix(y_test, predictions)

# Tính toán đường cong ROC
fpr, tpr, _ = roc_curve(y_test, probabilities)
roc_auc = auc(fpr, tpr)

# Tính toán đường cong Precision-Recall
precision, recall, _ = precision_recall_curve(y_test, probabilities)
pr_auc = auc(recall, precision)

# Trích xuất và sắp xếp feature importances
importances = clf.best_estimator_.feature_importances_
feature_importance = dict(zip(features, importances))
sorted_importance = dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True))

# 6. Lưu mô hình
print("=== GIAI ĐOẠN 6: LƯU MÔ HÌNH ===")
# Lưu mô hình tốt nhất vào file pickle
with open('../models/model-random-forest.pkl', 'wb') as file:
    pickle.dump(clf.best_estimator_, file)
print("Model saved successfully as '../models/model-random-forest.pkl'")

# 7. Tạo một visualization duy nhất chứa tất cả thông tin
print("=== GIAI ĐOẠN 7: TẠO VISUALIZATION TỔNG HỢP ===")

# Tạo một visualization duy nhất
plt.figure(figsize=(16, 16))

# Thiết lập tổng thể
plt.suptitle('Network Traffic Classification Model Summary', fontsize=20, y=0.98)

# Định nghĩa các khu vực chính
gs = plt.GridSpec(4, 2, height_ratios=[1, 1.2, 1.2, 0.6])

# Khu vực 1: Thông tin tổng quan về dataset và preprocessing
ax1 = plt.subplot(gs[0, 0])
ax1.axis('off')
ax1.text(0.5, 1.0, 'Dataset & Preprocessing', fontsize=14, weight='bold', ha='center', va='top')
dataset_info = [
    f"• Features: {', '.join(features)}",
    f"• Labels: Benign (0), Malicious (1)",
    f"• Preprocessing: NaN/Inf removed, MinMaxScaler applied",
    f"• Before Balance: Benign ({pre_balance_counts['Benign']:,}), Malicious ({pre_balance_counts['Malicious']:,})",
    f"• After Balance: Benign ({post_balance_counts['Benign']:,}), Malicious ({post_balance_counts['Malicious']:,})",
    f"• Train-Test Split: {len(train):,} train samples, {len(test):,} test samples (70/30)"
]
y_pos = 0.9
for info in dataset_info:
    ax1.text(0.05, y_pos, info, fontsize=10, ha='left', va='top')
    y_pos -= 0.15

# Khu vực 2: Thông tin mô hình và training
ax2 = plt.subplot(gs[0, 1])
ax2.axis('off')
ax2.text(0.5, 1.0, 'Model & Training', fontsize=14, weight='bold', ha='center', va='top')
model_info = [
    f"• Algorithm: RandomForestClassifier",
    f"• Hyperparameter Tuning: GridSearchCV with 5-fold CV",
    f"• Best n_estimators: {best_n_estimators}",
    f"• Best CV Score: {best_cv_score:.4f}",
    f"• Training Time: {training_time:.2f} seconds",
    f"• Model Saved: ../models/model-random-forest.pkl"
]
y_pos = 0.9
for info in model_info:
    ax2.text(0.05, y_pos, info, fontsize=10, ha='left', va='top')
    y_pos -= 0.15

# Khu vực 3: Confusion Matrix
ax3 = plt.subplot(gs[1, 0])
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False, ax=ax3)
ax3.set_title('Confusion Matrix')
ax3.set_xlabel('Predicted')
ax3.set_ylabel('Actual')
ax3.set_xticklabels(['Benign (0)', 'Malicious (1)'])
ax3.set_yticklabels(['Benign (0)', 'Malicious (1)'])

# Khu vực 4: Các metrics đánh giá
ax4 = plt.subplot(gs[1, 1])
ax4.axis('off')
ax4.text(0.5, 1.0, 'Evaluation Metrics', fontsize=14, weight='bold', ha='center', va='top')
metrics_info = [
    f"• Accuracy: {accuracy:.4f}",
    f"• ROC AUC: {roc_auc:.4f}",
    f"• F1 Score: {f1:.4f}",
    f"• Precision-Recall AUC: {pr_auc:.4f}"
]
y_pos = 0.9
for info in metrics_info:
    ax4.text(0.05, y_pos, info, fontsize=12, ha='left', va='top')
    y_pos -= 0.15

# Thêm thông tin từ classification report
report_lines = report.split('\n')
ax4.text(0.05, 0.3, 'Classification Report:', fontsize=12, weight='bold', ha='left', va='top')
y_pos = 0.25
for i, line in enumerate(report_lines[1:7]):  # Chỉ lấy phần quan trọng của report
    if line.strip():  # Kiểm tra xem dòng có trống không
        ax4.text(0.05, y_pos, line, fontsize=10, ha='left', va='top', family='monospace')
        y_pos -= 0.08

# Khu vực 5: Feature Importance
ax5 = plt.subplot(gs[2, :])
importance_values = list(sorted_importance.values())
importance_names = list(sorted_importance.keys())

# Tạo barplot các feature importance
ax5.barh(range(len(importance_names)), importance_values, color='skyblue')
ax5.set_yticks(range(len(importance_names)))
ax5.set_yticklabels(importance_names)
ax5.set_title('Feature Importance')
ax5.set_xlabel('Importance Score')

# Thêm giá trị lên mỗi bar
for i, v in enumerate(importance_values):
    ax5.text(v + 0.01, i, f'{v:.4f}', va='center')

# Khu vực 6: ROC và PR Curves (chỉ các giá trị AUC)
ax6 = plt.subplot(gs[3, :])
ax6.axis('off')
ax6.text(0.5, 0.9, 'Curve Metrics (without plots)', fontsize=14, weight='bold', ha='center', va='top')
ax6.text(0.3, 0.7, f'ROC Curve AUC: {roc_auc:.4f}', fontsize=12, ha='center')
ax6.text(0.7, 0.7, f'Precision-Recall Curve AUC: {pr_auc:.4f}', fontsize=12, ha='center')
ax6.text(0.5, 0.4, 'For complete details see console output.', fontsize=10, ha='center', style='italic')

plt.tight_layout(rect=[0, 0, 1, 0.97])
plt.savefig(f"{output_dir}/comprehensive_model_summary.png", dpi=300, bbox_inches='tight')
plt.close()

print(f"Comprehensive model summary created: {output_dir}/comprehensive_model_summary.png")