# file_manager.py
import csv
import pyshark
from tkinter import filedialog, messagebox
from scapy.all import wrpcap
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from ip_geolocation import IPGeolocation

def open_file(app):
    """
    Mở file PCAP, đọc các gói tin và cập nhật vào app.packet_list.
    Đồng thời hiển thị từng gói tin qua hàm display_packet của app.
    """
    file_path = filedialog.askopenfilename(
        filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")]
    )
    if file_path:
        app.packet_list.clear()  # Xóa nội dung cũ của list
        app.capture = pyshark.FileCapture(file_path)
        for packet in app.capture:
            app.packet_list.append(packet)
            app.display_packet(packet)

def save_to_csv(app):
    """
    Lưu dữ liệu trong app.packet_list vào file CSV.
    """
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
    )
    if file_path:
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(
                ["No.", "Time", "Source", "Destination", "Protocol", "Length",
                 "Src_Country", "Src_City", "Src_Time_Zone", "Src_Service"]
            )
            for idx, packet in enumerate(app.packet_list, start=1):
                if 'ip' in packet:
                    source_ip = packet.ip.src
                    dest_ip = packet.ip.dst
                    source_geo = IPGeolocation(source_ip)
                    writer.writerow([
                        idx,
                        packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
                        source_ip,
                        dest_ip,
                        packet.transport_layer,
                        packet.length,
                        source_geo.country,
                        source_geo.city,
                        source_geo.time_zone,
                        source_geo.isp
                    ])
        messagebox.showinfo("Save to CSV", "Data saved successfully!")

def export_to_csv(app):
    """
    Hàm export_to_csv chỉ gọi đến save_to_csv.
    """
    save_to_csv(app)

def save_to_pcap(app):
    """
    Lưu dữ liệu trong app.packet_list thành file PCAP sử dụng Scapy.
    """
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pcap",
        filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")]
    )
    if file_path:
        scapy_packets = []
        for packet in app.packet_list:
            if 'ip' in packet:
                ip_packet = IP(src=packet.ip.src, dst=packet.ip.dst)
                if 'eth' in packet:
                    ether_packet = Ether(src=packet.eth.src, dst=packet.eth.dst)
                    scapy_packets.append(ether_packet / ip_packet)
                else:
                    scapy_packets.append(ip_packet)
        wrpcap(file_path, scapy_packets)
        messagebox.showinfo("Save to PCAP", "PCAP file saved successfully!")
