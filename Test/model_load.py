import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import queue
import pandas as pd
import asyncio
import nest_asyncio
from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
from datetime import datetime

# Apply nest_asyncio to allow asyncio to work in Tkinter's mainloop
nest_asyncio.apply()

class FlowKey:
    """A key class to identify unique flows based on IP addresses, ports and protocol"""
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
    def __eq__(self, other):
        if not isinstance(other, FlowKey):
            return False
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port and
                self.protocol == other.protocol)
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))
    
    def reverse(self):
        """Create a reversed flow key (for bidirectional matching)"""
        return FlowKey(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)


class Flow:
    """Class representing a network flow with features"""
    def __init__(self, key):
        self.key = key
        self.start_time = None
        self.last_time = None
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.protocol = key.protocol
        self.dst_port = key.dst_port
        self.src_ip = key.src_ip
        self.dst_ip = key.dst_ip
        self.label = "Loading..."
        
    @property
    def flow_duration(self):
        """Calculate flow duration in seconds"""
        if self.start_time and self.last_time:
            return (self.last_time - self.start_time).total_seconds()
        return 0
    
    def to_feature_vector(self):
        """Convert flow to feature vector for ML model with all integers"""
        # Directly use numeric representation for protocol
        protocol_num = 0  # Default for other protocols
        if self.protocol == 'TCP':
            protocol_num = 6
        elif self.protocol == 'UDP':
            protocol_num = 17
            
        # Convert flow duration to integer (milliseconds)
        duration_ms = int(self.flow_duration * 1000)
            
        return [
            int(self.dst_port),  # Ensure port is integer
            int(protocol_num),   # Protocol as integer
            duration_ms,         # Duration in milliseconds as integer
            int(self.fwd_packets),  # Forward packets as integer
            int(self.bwd_packets)   # Backward packets as integer
        ]
    
    def to_dict(self):
        """Convert flow to dictionary for display"""
        return {
            'Src IP': self.src_ip,
            'Dst IP': self.dst_ip,
            'Dst Port': self.dst_port,
            'Protocol': self.protocol,  # Keep as string for display
            'Flow Duration': f"{self.flow_duration:.4f}s",
            'Tot Fwd Pkts': self.fwd_packets,
            'Tot Bwd Pkts': self.bwd_packets,
            'Label': self.label
        }
        
class PacketAnalyzer:
    """Main analyzer class that captures and processes packets"""
    def __init__(self, interface=None):
        self.interface = interface
        self.flows = {}
        self.flow_lock = threading.Lock()
        self.packet_queue = queue.Queue()
        self.is_capturing = False
        self.model = None
        self.model_loaded = False
        self.model_queue = queue.Queue()
        
    def load_model(self):
        """Load the ML model from model.pkl file"""
        print("Loading model...")
        try:
            # Load the trained model from a file
            self.model = joblib.load('model.pkl')
            self.model_loaded = True
            print("Model loaded successfully")
        except Exception as e:
            print(f"Error loading model: {e}")
            # Fallback to a dummy model if loading fails
            class DummyModel:
                def predict(self, X):
                    return ["benign" for _ in X]  # Default to benign
            self.model = DummyModel()
            self.model_loaded = True
            print("Using fallback model due to error")
    
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.is_capturing:
            return
            
        self.is_capturing = True
        
        # Start model loading in a separate thread
        threading.Thread(target=self.load_model, daemon=True).start()
        
        # Start packet processing thread
        threading.Thread(target=self.process_packets, daemon=True).start()
        
        # Start packet capturing thread
        threading.Thread(target=self._capture_packets, daemon=True).start()
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
    
    def _capture_packets(self):
        """Capture packets using Scapy"""
        try:
            sniff(iface=self.interface, prn=self._packet_callback, store=False, 
                  stop_filter=lambda p: not self.is_capturing)
        except Exception as e:
            print(f"Error in packet capture: {e}")
    
    def _packet_callback(self, packet):
        """Callback function for each captured packet"""
        if not (IP in packet):
            return
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = None
        src_port = 0
        dst_port = 0
        
        if TCP in packet:
            protocol = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            # Skip non-TCP/UDP packets for simplicity
            return
        
        # Create flow key
        flow_key = FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
        
        # Add packet to queue for processing
        self.packet_queue.put((flow_key, datetime.now()))
    
    def process_packets(self):
        """Process packets from the queue and update flows"""
        while self.is_capturing:
            try:
                flow_key, timestamp = self.packet_queue.get(timeout=1)
                
                with self.flow_lock:
                    # Check if this is a new flow or part of an existing flow (forward or backward)
                    if flow_key in self.flows:
                        flow = self.flows[flow_key]
                        flow.fwd_packets += 1
                    elif flow_key.reverse() in self.flows:
                        flow = self.flows[flow_key.reverse()]
                        flow.bwd_packets += 1
                    else:
                        # New flow
                        flow = Flow(flow_key)
                        flow.start_time = timestamp
                        flow.fwd_packets = 1
                        self.flows[flow_key] = flow
                    
                    # Update the last seen timestamp
                    flow.last_time = timestamp
                    
                    # Try to predict label if model is loaded
                    if self.model_loaded and flow.label == "Loading...":
                        try:
                            features = np.array([flow.to_feature_vector()])
                            prediction = self.model.predict(features)[0]
                            # Make sure the label is a string
                            flow.label = str(prediction)
                            self.model_queue.put(flow)
                        except Exception as e:
                            print(f"Error predicting flow label: {e}")
                            flow.label = "Error"
                            self.model_queue.put(flow)
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error processing packet: {e}")
    
    def get_flows(self):
        """Get all current flows"""
        with self.flow_lock:
            return [flow.to_dict() for flow in self.flows.values()]
    
    def get_updated_flow(self):
        """Get a flow with updated label (non-blocking)"""
        try:
            return self.model_queue.get_nowait()
        except queue.Empty:
            return None


class NetworkAnalyzerGUI:
    """Tkinter GUI for the network flow analyzer"""
    def __init__(self, root):
        self.root = root
        self.root.title("Network Flow Analyzer")
        self.root.geometry("1200x600")  # Increased width to accommodate IP columns
        
        self.analyzer = PacketAnalyzer()
        self.create_widgets()
        self.update_table()
    
    def create_widgets(self):
        """Create GUI widgets"""
        # Control frame
        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.pack(fill=tk.X)
        
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Status indicator for model
        self.model_status = ttk.Label(control_frame, text="Model: Not Loaded")
        self.model_status.pack(side=tk.RIGHT, padx=5)
        
        # Table frame
        table_frame = ttk.Frame(self.root, padding=10)
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create Treeview with IP columns added
        columns = ['Src IP', 'Dst IP', 'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'Label']
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings')
        
        # Configure column headings
        for col in columns:
            self.tree.heading(col, text=col)
            width = 150 if 'IP' in col else 100  # Make IP columns wider
            self.tree.column(col, width=width, anchor=tk.CENTER)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def start_capture(self):
        """Start packet capture"""
        self.analyzer.start_capture()
        self.status_var.set("Capturing packets...")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Update model status periodically
        self.check_model_status()
    
    def check_model_status(self):
        """Check and update the model loading status"""
        if self.analyzer.model_loaded:
            self.model_status.config(text="Model: Loaded")
        else:
            self.model_status.config(text="Model: Loading...")
            self.root.after(500, self.check_model_status)
    
    def stop_capture(self):
        """Stop packet capture"""
        self.analyzer.stop_capture()
        self.status_var.set("Capture stopped")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def update_table(self):
        """Update the table with current flows"""
        try:
            # Check for flows with updated labels
            updated_flow = self.analyzer.get_updated_flow()
            if updated_flow:
                # Find and update the row with this flow
                for item_id in self.tree.get_children():
                    item = self.tree.item(item_id)
                    if (item['values'][2] == updated_flow.dst_port and  # Index changed because of added IP columns
                        item['values'][3] == updated_flow.protocol and
                        item['values'][0] == updated_flow.src_ip and
                        item['values'][1] == updated_flow.dst_ip):
                        # Update the Label column
                        values = list(item['values'])
                        values[7] = updated_flow.label  # Index changed to 7 because of added IP columns
                        
                        # Apply color based on label
                        if updated_flow.label.lower() == "malicious":
                            self.tree.item(item_id, values=values, tags=('malicious',))
                        else:
                            self.tree.item(item_id, values=values, tags=('benign',))
            
            # Configure tag colors
            self.tree.tag_configure('malicious', background='#ffcccc')  # Light red for malicious
            self.tree.tag_configure('benign', background='#ccffcc')  # Light green for benign
            
            if self.analyzer.is_capturing:
                # Get current flows
                flows = self.analyzer.get_flows()
                
                # Save existing items to avoid recreation (reduces flicker)
                existing_items = {}
                for item_id in self.tree.get_children():
                    item = self.tree.item(item_id)
                    key = (item['values'][0], item['values'][1], item['values'][2], item['values'][3])
                    existing_items[key] = item_id
                
                # Update or create items
                current_items = set()
                for flow in flows:
                    values = [
                        flow['Src IP'],
                        flow['Dst IP'],
                        flow['Dst Port'],
                        flow['Protocol'],
                        flow['Flow Duration'],
                        flow['Tot Fwd Pkts'],
                        flow['Tot Bwd Pkts'],
                        flow['Label']
                    ]
                    
                    key = (flow['Src IP'], flow['Dst IP'], flow['Dst Port'], flow['Protocol'])
                    current_items.add(key)
                    
                    tag = 'benign' if flow['Label'].lower() == 'benign' else 'malicious' if flow['Label'].lower() == 'malicious' else ''
                    
                    if key in existing_items:
                        # Update existing item
                        self.tree.item(existing_items[key], values=values, tags=(tag,) if tag else ())
                    else:
                        # Create new item
                        self.tree.insert('', tk.END, values=values, tags=(tag,) if tag else ())
                
                # Remove items that no longer exist
                for key, item_id in list(existing_items.items()):
                    if key not in current_items:
                        self.tree.delete(item_id)
                
        except Exception as e:
            print(f"Error updating table: {e}")
        
        # Schedule the next update
        self.root.after(1000, self.update_table)


if __name__ == "__main__":
    # Create and start the GUI
    root = tk.Tk()
    app = NetworkAnalyzerGUI(root)
    root.mainloop()