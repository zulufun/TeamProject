import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import pandas as pd


class FlowVisualization:
    """Class for visualizing flow data with charts and graphs"""

    def __init__(self, master, flow_data=None):
        self.master = master
        self.flow_data = flow_data if flow_data else []

        # Create the visualization window
        self.window = tk.Toplevel(master)
        self.window.title("Flow Data Visualization")
        self.window.geometry("1000x800")

        # Create notebook for different visualizations
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create tabs for different visualizations
        self.protocol_tab = ttk.Frame(self.notebook)
        self.data_volume_tab = ttk.Frame(self.notebook)
        self.flow_duration_tab = ttk.Frame(self.notebook)
        self.packet_size_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.protocol_tab, text="Protocols")
        self.notebook.add(self.data_volume_tab, text="Data Volume")
        self.notebook.add(self.flow_duration_tab, text="Flow Duration")
        self.notebook.add(self.packet_size_tab, text="Packet Size")

        # Create the charts if data is provided
        if self.flow_data:
            self.create_visualizations()

    def set_flow_data(self, flow_data):
        """Update the flow data and refresh visualizations"""
        self.flow_data = flow_data
        self.create_visualizations()

    def create_visualizations(self):
        """Create all visualizations based on the flow data"""
        if not self.flow_data:
            return

        # Convert flow data to DataFrame for easier analysis
        df = pd.DataFrame(self.flow_data)

        # Create protocol distribution visualization
        self.create_protocol_chart(df)

        # Create data volume visualization
        self.create_data_volume_chart(df)

        # Create flow duration visualization
        self.create_flow_duration_chart(df)

        # Create packet size visualization
        self.create_packet_size_chart(df)

    def create_protocol_chart(self, df):
        """Create protocol distribution chart"""
        # Clear any existing widgets
        for widget in self.protocol_tab.winfo_children():
            widget.destroy()

        # Create figure and axis
        fig, ax = plt.subplots(figsize=(10, 6))

        # Check if protocol column exists
        if 'protocol' in df.columns:
            # Count protocols
            protocol_counts = df['protocol'].value_counts()

            # Create pie chart
            ax.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%',
                   shadow=True, startangle=90)
            ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
            ax.set_title('Protocol Distribution')

            # Create canvas
            canvas = FigureCanvasTkAgg(fig, master=self.protocol_tab)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            # Display message if protocol column doesn't exist
            label = ttk.Label(self.protocol_tab, text="Protocol data not available")
            label.pack(pady=20)

    def create_data_volume_chart(self, df):
        """Create data volume visualization"""
        # Clear any existing widgets
        for widget in self.data_volume_tab.winfo_children():
            widget.destroy()

        # Create frame for controls
        control_frame = ttk.Frame(self.data_volume_tab)
        control_frame.pack(fill=tk.X, pady=5)

        # Group by source IP or destination IP
        group_label = ttk.Label(control_frame, text="Group by:")
        group_label.pack(side=tk.LEFT, padx=5)

        group_var = tk.StringVar(value="src_ip")
        src_radio = ttk.Radiobutton(control_frame, text="Source IP", variable=group_var,
                                    value="src_ip", command=lambda: update_chart())
        dst_radio = ttk.Radiobutton(control_frame, text="Destination IP", variable=group_var,
                                    value="dst_ip", command=lambda: update_chart())
        src_radio.pack(side=tk.LEFT, padx=5)
        dst_radio.pack(side=tk.LEFT, padx=5)

        # Create chart frame
        chart_frame = ttk.Frame(self.data_volume_tab)
        chart_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        def update_chart():
            # Clear chart frame
            for widget in chart_frame.winfo_children():
                widget.destroy()

            # Create figure and axis
            fig, ax = plt.subplots(figsize=(10, 6))

            group_field = group_var.get()

            if group_field in df.columns and 'total_bytes' in df.columns:
                # Group by IP and sum bytes
                grouped_data = df.groupby(group_field)['total_bytes'].sum().sort_values(ascending=False).head(10)

                # Bar chart
                bars = ax.bar(grouped_data.index, grouped_data.values)

                # Add labels
                ax.set_xlabel('IP Address')
                ax.set_ylabel('Total Bytes')
                ax.set_title(f'Top 10 IPs by Data Volume ({group_field})')

                # Rotate x-axis labels
                plt.xticks(rotation=45, ha='right')

                # Add data labels on bars
                for bar in bars:
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width() / 2., height,
                            f'{height:,}',
                            ha='center', va='bottom', rotation=0)

                fig.tight_layout()

                # Create canvas
                canvas = FigureCanvasTkAgg(fig, master=chart_frame)
                canvas.draw()
                canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            else:
                # Display message if required columns don't exist
                label = ttk.Label(chart_frame, text="Required data not available")