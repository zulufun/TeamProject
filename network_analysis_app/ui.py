import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from file_operations import open_file, save_to_csv, save_to_pcap
from capture import PacketCapture  # Assuming this is defined elsewhere
import psutil


class WiresharkApp:
    def __init__(self, master):
        self.master = master
        master.title("Wireshark App")

        # Menu setup
        self.menu = tk.Menu(master)
        master.config(menu=self.menu)

        # Add menus
        self.file_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open", command=self.open_file)
        self.file_menu.add_command(label="Save to PCAP", command=self.save_to_pcap)
        self.file_menu.add_command(label="Save to CSV", command=self.save_to_csv)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=master.quit)

        self.stats_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="Stats", menu=self.stats_menu)
        self.stats_menu.add_command(label="Source Country Distribution", command=self.show_source_country_stats)
        self.stats_menu.add_command(label="Source Service Distribution", command=self.show_source_service_stats)

        self.help_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_help_message)

        # UI components
        self.setup_ui()

        # Packet management
        self.packet_capture = PacketCapture(self)
        self.packet_list = []  # To store captured packets

    def setup_ui(self):
        """Set up interface and layout."""
        # Interface frame
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

        # Packet treeview
        self.tree = ttk.Treeview(self.master, columns=("No.", "Time", "Source", "Destination", "Protocol", "Length"), show="headings")
        self.tree.heading("No.", text="No.")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        self.tree.pack(fill=tk.BOTH, expand=True)

    def populate_interfaces(self):
        """Populate network interfaces."""
        try:
            interfaces = psutil.net_if_addrs()
            self.interface_combobox['values'] = [name for name in interfaces.keys()]
            if interfaces:
                self.interface_combobox.current(0)
        except Exception as e:
            print(f"Error populating interfaces: {e}")

    # Menu command methods
    def open_file(self):
        """Open a PCAP file."""
        open_file(self)

    def save_to_csv(self):
        """Save captured packets to a CSV file."""
        save_to_csv(self.packet_list)

    def save_to_pcap(self):
        """Save captured packets to a PCAP file."""
        save_to_pcap(self.packet_list)

    def show_source_country_stats(self):
        """Placeholder for showing source country stats."""
        messagebox.showinfo("Stats", "Source Country Distribution stats not implemented yet.")

    def show_source_service_stats(self):
        """Placeholder for showing source service stats."""
        messagebox.showinfo("Stats", "Source Service Distribution stats not implemented yet.")

    def show_help_message(self):
        """Show an About dialog."""
        messagebox.showinfo("About", "Wireshark App\nDeveloped by Your Name.\nVersion 1.0")

    # Capture-related methods
    def start_capture(self):
        """Start packet capture."""
        interface = self.interface_combobox.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.packet_list = []  # Reset packet list
        self.packet_capture.start(interface)

    def stop_capture(self):
        """Stop packet capture."""
        self.packet_capture.stop()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()
