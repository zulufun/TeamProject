import tkinter as tk
from tkinter import ttk
import win32evtlog
import threading
import time
import datetime


class EventViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Event Viewer Log Extractor with Controlled Scrolling")

        # Configure layout
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        # Treeview for log display
        self.log_tree = ttk.Treeview(
            root,
            columns=("Time", "Source", "Category", "Message"),
            show="headings",
            selectmode="browse"
        )
        self.log_tree.heading("Time", text="Time")
        self.log_tree.heading("Source", text="Source")
        self.log_tree.heading("Category", text="Category")
        self.log_tree.heading("Message", text="Message")
        self.log_tree.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # Scrollbar for Treeview
        tree_scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.grid(row=0, column=0, sticky="nse")

        # Start extraction button
        self.extract_button = tk.Button(root, text="Start Realtime Extract", command=self.start_realtime_extract)
        self.extract_button.grid(row=1, column=0, pady=5)

        self.running = False
        self.seen_events = set()  # To store seen event IDs
        self.log_entries = []  # Store log entries for sorting

    def start_realtime_extract(self):
        if not self.running:
            self.running = True
            self.extract_button.config(state=tk.DISABLED)
            threading.Thread(target=self.extract_logs, daemon=True).start()

    def extract_logs(self):
        server = 'localhost'
        log_type = 'Application'  # Change to 'System' or 'Security' if needed

        hand = win32evtlog.OpenEventLog(server, log_type)

        while self.running:
            try:
                # Read logs backwards (newest to oldest)
                events = win32evtlog.ReadEventLog(
                    hand,
                    win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                    0
                )
                if events:
                    for event in events:
                        event_id = event.RecordNumber
                        if event_id in self.seen_events:
                            continue  # Skip already processed logs

                        self.seen_events.add(event_id)
                        event_time = event.TimeGenerated.Format() if event.TimeGenerated else "N/A"
                        source = event.SourceName
                        category = event.EventCategory
                        message = " ".join(event.StringInserts) if event.StringInserts else "No message"

                        log_entry = {
                            "time": event.TimeGenerated,  # datetime object for sorting
                            "source": source,
                            "category": category,
                            "message": message
                        }

                        self.log_entries.append(log_entry)

                # Sort the logs from oldest to newest
                self.log_entries.sort(key=lambda x: x["time"])

                # Update the Treeview with sorted logs
                self.update_treeview()

            except Exception as e:
                print(f"Error reading event log: {e}")

            time.sleep(5)  # Check for new logs every 5 seconds

    def update_treeview(self):
        """Update Treeview with sorted logs."""
        # Get the current position of the Scrollbar
        yview_position = self.log_tree.yview()

        # Clear existing logs in the Treeview
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)

        # Insert logs into the Treeview
        for log_entry in self.log_entries:
            self.log_tree.insert(
                "", "end",
                values=(
                    log_entry["time"].strftime("%Y-%m-%d %H:%M:%S"),
                    log_entry["source"],
                    log_entry["category"],
                    log_entry["message"]
                )
            )

        # Automatically scroll to the end only if Scrollbar is near the bottom
        if yview_position[1] > 0.95:  # If Scrollbar is at 95% or closer to the bottom
            self.log_tree.yview_moveto(1.0)  # Scroll to the bottom


# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = EventViewerApp(root)
    root.mainloop()
