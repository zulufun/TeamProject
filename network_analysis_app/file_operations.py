import csv
from tkinter import filedialog, messagebox
from scapy.all import wrpcap
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

def open_file(app):
    """Open a PCAP file and load its contents into the app."""
    file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
    if file_path:
        try:
            app.packet_capture.load_from_file(file_path)
            messagebox.showinfo("Open File", f"Successfully loaded packets from {file_path}.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {e}")

def save_to_csv(packet_list):
    """Save captured packets to a CSV file."""
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
    if file_path:
        try:
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length"])
                for idx, packet in enumerate(packet_list, start=1):
                    if hasattr(packet, 'ip'):
                        writer.writerow([
                            idx,
                            packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
                            packet.ip.src,
                            packet.ip.dst,
                            packet.transport_layer if hasattr(packet, 'transport_layer') else '',
                            packet.length
                        ])
            messagebox.showinfo("Save to CSV", "Data saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save to CSV: {e}")

def save_to_pcap(packet_list):
    """Save captured packets to a PCAP file."""
    file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                             filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
    if file_path:
        try:
            scapy_packets = []
            for packet in packet_list:
                if hasattr(packet, 'ip'):
                    ip_packet = IP(src=packet.ip.src, dst=packet.ip.dst)
                    if hasattr(packet, 'eth'):
                        ether_packet = Ether(src=packet.eth.src, dst=packet.eth.dst)
                        scapy_packets.append(ether_packet / ip_packet)
                    else:
                        scapy_packets.append(ip_packet)
            wrpcap(file_path, scapy_packets)
            messagebox.showinfo("Save to PCAP", "PCAP file saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save to PCAP: {e}")
