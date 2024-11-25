import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
import threading
import psutil
import matplotlib.pyplot as plt
from capture import PacketCapture
from ip_geolocation import IPGeolocation
from file_operations import FileOperations
import asyncio
class WiresharkApp:
    def __init__(self, master):
        self.master = master
        master.title("Wireshark App")
        self.setup_menu()
        self.setup_ui()
        self.capture = None
        self.capture_thread = None
        self.running = False
        self.packet_list = []
        self.filtered_packets = []
        self.file_operations = FileOperations(self.packet_list)  # Initialize FileOperations

    def setup_menu(self):
        self.menu = tk.Menu(self.master)
        self.master.config(menu=self.menu)

        self.file_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open", command=self.open_file)
        self.file_menu.add_command(label="Save to PCAP", command=self.save_to_pcap)  # Gọi phương thức save_to_pcap
        self.file_menu.add_command(label="Save to CSV", command=self.save_to_csv)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.master.quit)

        self.help_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_help_message)

        self.stats_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="Stats", menu=self.stats_menu)
        self.stats_menu.add_command(label="Source Country Distribution", command=self.show_source_country_stats)
        self.stats_menu.add_command(label="Source Service Distribution", command=self.show_source_service_stats)

    def setup_ui(self):
        # Frame for interface selection and control buttons
        self.interface_frame = tk.Frame(self.master)
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
        self.continue_button = tk.Button(self.interface_frame, text="Continue", command=self.continue_capture, state=tk.DISABLED)
        self.continue_button.grid(row=0, column=4, padx=5)
        self.export_button = tk.Button(self.interface_frame, text="Export to CSV", command=self.export_to_csv, state=tk.DISABLED)
        self.export_button.grid(row=0, column=5, padx=5)

        # Filter section
        self.filter_frame = tk.Frame(self.master)
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

        # Treeview for displaying packets
        self.tree = ttk.Treeview(self.master, columns=(
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Src_Country", "Src_City", "Src_Time_Zone",
            "Src_Service"), show="headings")
        self.tree.heading("No.", text="No.")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        self.tree.heading("Src_Country", text="Src Country")
        self.tree.heading("Src_City", text="Src City")
        self.tree.heading("Src_Time_Zone", text="Src Time Zone")
        self.tree.heading("Src_Service", text="Src Service")

        # Default column widths
        column_widths = {
            "No.": 50,
            "Time": 150,
            "Source": 100,
            "Destination": 100,
            "Protocol": 80,
            "Length": 80,
            "Src_Country": 100,
            "Src_City": 100,
            "Src_Time_Zone": 100,
            "Src_Service": 100,
        }
        for column, width in column_widths.items():
            self.tree.column(column, width=width, anchor=tk.CENTER)

        self.tree.bind("<ButtonRelease-1>", self.display_packet_details)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Scrollbar for Treeview
        self.scrollbar = ttk.Scrollbar(self.master, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # Log ScrolledText widget
        self.log = scrolledtext.ScrolledText(self.master, width=60, height=10)
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
            elif filter_field == "Protocol" and hasattr(packet, 'transport_layer') and packet.transport_layer == filter_text:
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
            self.packet_list = []
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
        self.capture = PacketCapture(interface)
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
    #From file_operations
    def open_file(self):
        self.packet_list = self.file_operations.open_file()
        self.display_packets(self.packet_list)
    def save_to_csv(self):
        self.file_operations.save_to_csv()
    def save_to_pcap(self):
        self.file_operations.save_to_pcap()  # Gọi phương thức save_to_pcap từ FileOperations
    def export_to_csv(self):
        self.save_to_csv()
################
    def show_help_message(self):
        messagebox.showinfo("Liên hệ", "Flow Link \nGithub : https://github.com/zulufun/App_WireShark")

    def display_packet_details(self, event):
        item = self.tree.selection()
        if item:
            item = item[0]
            packet = self.packet_list[int(self.tree.item(item, "values")[0 ]) - 1]
            self.log.delete(1.0, tk.END)
            self.log.insert(tk.END, str(packet))

    def show_source_country_stats(self):
        self.stats_thread = threading.Thread(target=self.generate_source_country_stats)
        self.stats_thread.start()

    def show_source_service_stats(self):
        self.stats_thread = threading.Thread(target=self.generate_source_service_stats)
        self.stats_thread.start()

    def generate_source_country_stats(self):
        src_country_count = {}
        for packet in self.packet_list:
            if 'ip' in packet:
                source_ip = packet.ip.src
                source_geo = IPGeolocation(source_ip)
                src_country = source_geo.country

                if src_country:
                    if src_country in src_country_count:
                        src_country_count[src_country] += 1
                    else:
                        src_country_count[src_country] = 1

        self.master.after(0, self.plot_pie_chart, src_country_count, "Source Country Distribution")

    def generate_source_service_stats(self):
        src_service_count = {}

        for packet in self.packet_list:
            if 'ip' in packet:
                source_ip = packet.ip.src
                source_geo = IPGeolocation(source_ip)
                src_service = source_geo.isp

                if src_service:
                    if src_service in src_service_count:
                        src_service_count[src_service] += 1
                    else:
                        src_service_count[src_service] = 1

        self.master.after(0, self.plot_pie_chart, src_service_count, "Source Service Distribution")

    def plot_pie_chart(self, data, title):
        labels = list(data.keys())
        sizes = list(data.values())
        plt.figure(figsize=(10, 6))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title(title)
        plt.axis('equal')
        plt.show()