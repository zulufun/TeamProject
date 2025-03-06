import pyshark

# Chọn giao diện thích hợp (ví dụ: 'Wi-Fi')
capture = pyshark.LiveCapture(interface='Wi-Fi')

# Bắt 1 gói tin
packet = next(capture.sniff_continuously(packet_count=1))
print("=== Đã bắt được gói tin ===\n")

# Duyệt qua từng lớp trong gói tin
for layer in packet:
    print(f"Layer: {layer.layer_name}")
    # Lấy danh sách các trường của lớp hiện tại
    fields = layer.field_names
    if fields:
        for field in fields:
            # Lấy giá trị của field (sử dụng method get_field)
            try:
                value = layer.get_field(field)
            except Exception as e:
                value = f"Error: {e}"
            print(f"  {field}: {value}")
    else:
        print("  Không có trường nào.")
    print("-" * 50)
