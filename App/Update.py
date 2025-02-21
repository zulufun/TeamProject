import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
import pyshark
import threading
import csv
import asyncio
import psutil
from scapy.all import wrpcap
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

# Import các feature thêm
import log_feature  #
import speed_test
import LAN_device
from ip_geolocation import IPGeolocation
from stats_generator import StatsGenerator
# Import module quản lý file
import file_manager

class WiresharkApp:
    def __init__(self, master):
        self.master = master
        master.title("Wireshark App")
        # Khởi tạo các biến quan trọng; lưu ý: tạo ra 1 list duy nhất
        self.packet_list = []  # Danh sách các gói tin thu thập được
        self.filtered_packets = []
        self.capture = None
        self.capture_thread = None
        self.running = False

        # ----------------- Menu -----------------
        self.menu = tk.Menu(master)
        master.config(menu=self.menu)

        # File Menu
        # File Menu
        self.file_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        # Gọi đến các hàm từ file_manager thông qua lambda, truyền self vào.
        self.file_menu.add_command(label="Open", command=lambda: file_manager.open_file(self))
        self.file_menu.add_command(label="Save to PCAP", command=lambda: file_manager.save_to_pcap(self))
        self.file_menu.add_command(label="Save to CSV", command=lambda: file_manager.save_to_csv(self))
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=master.quit)

        # Extra Menu
        self.extra_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="Extra", menu=self.extra_menu)
        self.extra_menu.add_command(label="Log_analyze", command=lambda: log_feature.extra_future(self.master))
        self.extra_menu.add_command(label="Speed_test",
                                    command=lambda: speed_test.open_network_speed_test_window(self.master))
        self.extra_menu.add_command(label="Theo dõi mạng LAN",
                                    command=lambda: LAN_device.open_detailed_network_monitor_window(self.master))

        # Stats Menu
        self.stats_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="Stats", menu=self.stats_menu)
        # Tạo đối tượng StatsGenerator và truyền self.packet_list (không phải 1 list mới)
        self.stats_gen = StatsGenerator(master=master, packet_list=self.packet_list)
        # Chỉ truyền tham chiếu đến hàm, không gọi hàm ngay
        self.stats_menu.add_command(label="Source Country Distribution",
                                    command=self.stats_gen.show_source_country_stats)
        self.stats_menu.add_command(label="Source Service Distribution",
                                    command=self.stats_gen.show_source_service_stats)

        # ----------------- Top Frame (Logo, tiêu đề, ...) -----------------
        self.top_frame = tk.Frame(master)
        self.top_frame.pack(pady=10)
        # (Thêm logo, tiêu đề nếu cần)
        # ----------------- Interface Frame -----------------
        self.interface_frame = tk.Frame(master)
        self.interface_frame.pack(pady=10)

        self.label = tk.Label(self.interface_frame, text="Select interface:")
        self.label.grid(row=0, column=0, padx=5)

        self.interface_combobox = ttk.Combobox(self.interface_frame)
        self.interface_combobox.grid(row=0, column=1, padx=5)
        self.populate_interfaces()

        self.start_button = tk.Button(self.interface_frame, text="Start", command=self.start_capture)
        self.start_button.grid(row=0, column=2, padx=5)
        self.stop_button = tk.Button(self.interface_frame, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5)
        self.continue_button = tk.Button(self.interface_frame, text="Continue", command=self.continue_capture,
                                         state=tk.DISABLED)
        self.continue_button.grid(row=0, column=4, padx=5)
        self.export_button = tk.Button(self.interface_frame, text="Export to CSV", command=self.export_to_csv,
                                       state=tk.DISABLED)
        self.export_button.grid(row=0, column=5, padx=5)

        # ----------------- Filter Section -----------------
        self.filter_frame = tk.Frame(master)
        self.filter_frame.pack(pady=10)

        self.filter_field_label = tk.Label(self.filter_frame, text="Filter Field:")
        self.filter_field_label.grid(row=0, column=0, padx=5)

        self.filter_field_combobox = ttk.Combobox(self.filter_frame, values=["Source IP", "Destination IP", "Protocol"])
        self.filter_field_combobox.grid(row=0, column=1, padx=5)

        self.filter_entry_label = tk.Label(self.filter_frame, text="Filter Text:")
        self.filter_entry_label.grid(row=0, column=2, padx=5)

        self.filter_entry = tk.Entry(self.filter_frame)
        self.filter_entry.grid(row=0, column=3, padx=5)

        self.filter_button = tk.Button(self.filter_frame, text="Filter", command=self.start_filter_thread)
        self.filter_button.grid(row=0, column=4, padx=5)

        # ----------------- Treeview for Displaying Packets -----------------
        self.tree = ttk.Treeview(master, columns=(
        "No.", "Time", "Source", "Destination", "Protocol", "Length", "Src_Country", "Src_City", "Src_Time_Zone", "Src_Service"), show="headings")
        for col in (
        "No.", "Time", "Source", "Destination", "Protocol", "Length", "Src_Country", "Src_City", "Src_Time_Zone", "Src_Service"):
            self.tree.heading(col, text=col)
        column_widths = {"No.": 50, "Time": 150, "Source": 100, "Destination": 100, "Protocol": 80, "Length": 80,
                         "Src_Country": 100, "Src_City": 100, "Src_Time_Zone": 100, "Src_Service": 100}
        for col, width in column_widths.items():
            self.tree.column(col, width=width, anchor=tk.CENTER)
        self.tree.bind("<ButtonRelease-1>", self.display_packet_details)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # ----------------- Scrollbar for Treeview -----------------
        self.scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # ----------------- Log ScrolledText Widget -----------------
        self.log = scrolledtext.ScrolledText(master, width=60, height=10)
        self.log.pack(fill=tk.BOTH, expand=True)

    def populate_interfaces(self):
        try:
            interfaces = psutil.net_if_addrs()
            interface_names = [f"{name} ({addrs[0].address})" for name, addrs in interfaces.items()]
            self.interface_combobox['values'] = interface_names
            if interface_names:
                self.interface_combobox.current(0)
        except Exception as e:
            print(f"Error populating interfaces: {e}")

    def start_filter_thread(self):
        filter_field = self.filter_field_combobox.get()
        filter_text = self.filter_entry.get()
        self.filter_thread = threading.Thread(target=self.filter_packets, args=(filter_field, filter_text))
        self.filter_thread.start()

    def filter_packets(self, filter_field, filter_text):
        self.filtered_packets = []
        for packet in self.packet_list:
            if filter_field == "Source IP":
                if hasattr(packet, 'ip') and packet.ip.src == filter_text:
                    self.filtered_packets.append(packet)
            elif filter_field == "Destination IP":
                if hasattr(packet, 'ip') and packet.ip.dst == filter_text:
                    self.filtered_packets.append(packet)
            elif filter_field == "Protocol" and hasattr(packet,
                                                        'transport_layer') and packet.transport_layer == filter_text:
                self.filtered_packets.append(packet)
        self.display_packets(self.filtered_packets)

    def display_packets(self, packets):
        self.tree.delete(*self.tree.get_children())
        for idx, packet in enumerate(packets, start=1):
            if 'ip' in packet:
                source_ip = packet.ip.src
                dest_ip = packet.ip.dst
                source_geo = IPGeolocation(source_ip)
                self.tree.insert("", "end", values=(
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
                ))

    def start_capture(self):
        if not self.running:
            # Dùng clear() để xóa nội dung của list hiện tại thay vì tạo list mới.
            self.packet_list.clear()
            interface = self.interface_combobox.get().split()[0]
            self.capture_thread = threading.Thread(target=self.capture_packets, args=(interface,))
            self.capture_thread.start()
            self.running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.continue_button.config(state=tk.DISABLED)
            self.export_button.config(state=tk.NORMAL)

    def stop_capture(self):
        if self.running:
            self.running = False
            if self.capture:
                self.capture.close()
            self.log.insert(tk.END, "Capture stopped\n")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.continue_button.config(state=tk.NORMAL)
            self.export_button.config(state=tk.NORMAL)

    def continue_capture(self):
        if not self.running:
            interface = self.interface_combobox.get().split()[0]
            self.capture_thread = threading.Thread(target=self.capture_packets, args=(interface,))
            self.capture_thread.start()
            self.running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.continue_button.config(state=tk.DISABLED)
            self.export_button.config(state=tk.NORMAL)

    def capture_packets(self, interface):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.capture = pyshark.LiveCapture(interface=interface)
        for packet in self.capture.sniff_continuously():
            if not self.running:
                break
            self.packet_list.append(packet)
            self.display_packet(packet)
        loop.close()

    def display_packet(self, packet):
        if 'ip' in packet:
            source_ip = packet.ip.src
            dest_ip = packet.ip.dst
            source_geo = IPGeolocation(source_ip)
            self.tree.insert("", "end", values=(
                len(self.packet_list),
                packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
                source_ip,
                dest_ip,
                packet.transport_layer,
                packet.length,
                source_geo.country,
                source_geo.city,
                source_geo.time_zone,
                source_geo.isp
            ))
    def display_packet_details(self, event):
        item = self.tree.selection()
        if item:
            item = item[0]
            packet = self.packet_list[int(self.tree.item(item, "values")[0]) - 1]
            self.log.delete(1.0, tk.END)
            self.log.insert(tk.END, str(packet))


def main():
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()
if __name__ == "__main__":
    main()