import csv
from tkinter import filedialog, messagebox
import pyshark
from ip_geolocation import IPGeolocation
from scapy.all import wrpcap
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

class FileOperations:
    def __init__(self, packet_list):
        self.packet_list = packet_list

    def open_file(self):
        """Mở tệp PCAP và đọc các gói tin vào danh sách."""
        file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if file_path:
            self.packet_list.clear()
            capture = pyshark.FileCapture(file_path)
            for packet in capture:
                self.packet_list.append(packet)
            return self.packet_list

    def save_to_csv(self):
        """Lưu danh sách gói tin vào tệp CSV."""
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(
                    ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Src_Country", "Src_City",
                     "Src_Time_Zone", "Src_Service"])
                for idx, packet in enumerate(self.packet_list, start=1):
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

    def save_to_pcap(self):
        """Lưu danh sách gói tin vào tệp PCAP."""
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                                 filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if file_path:
            scapy_packets = []
            for packet in self.packet_list:
                if 'ip' in packet:
                    ip_packet = IP(src=packet.ip.src, dst=packet.ip.dst)
                    if 'eth' in packet:
                        ether_packet = Ether(src=packet.eth.src, dst=packet.eth.dst)
                        scapy_packets.append(ether_packet / ip_packet)
                    else:
                        scapy_packets.append(ip_packet)
            wrpcap(file_path, scapy_packets)
            messagebox.showinfo("Save to PCAP", "PCAP file saved successfully!")