import pyshark

capture = pyshark.LiveCapture(interface='Wi-Fi')
for packet in capture.sniff_continuously(packet_count=1):
    # In ra các lớp của gói tin
    for layer in packet:
        print(layer.layer_name)
        print(layer.field_names)