import pandas as pd
import numpy as np

# Đọc file dữ liệu gốc
df_dataset = pd.read_csv(r"../../Train_model/kaggel/input/solarmainframe/ids-intrusion-csv/versions/1/02-14-2018.csv")

# Chọn các cột cần thiết
selected_columns = ['Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'Label']
df_necessary = df_dataset[selected_columns]

# Xử lý dữ liệu: thay thế các giá trị vô cực và bỏ các giá trị bị thiếu
df_necessary.replace([np.inf, -np.inf], pd.NA, inplace=True)
df_necessary.dropna(inplace=True)

# Lưu data cần thiết vào file CSV riêng
df_necessary.to_csv('../export_model/necessary_data.csv', index=False)

print("Data cần thiết đã được lưu vào file 'necessary_data.csv'")
