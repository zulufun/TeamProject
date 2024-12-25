import tkinter as tk
from tkinter import ttk
import win32evtlog
import threading
import time
import ctypes


class EventViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Event Viewer - Administrative Logs")

        # Treeview for log display
        self.log_tree = ttk.Treeview(
            root,
            columns=("Time", "Source", "Level", "Category", "Message"),
            show="headings",
            selectmode="browse"
        )
        self.log_tree.heading("Time", text="Time")
        self.log_tree.heading("Source", text="Source")
        self.log_tree.heading("Level", text="Level")
        self.log_tree.heading("Category", text="Category")
        self.log_tree.heading("Message", text="Message")
        self.log_tree.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # Scrollbar for Treeview
        tree_scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.grid(row=0, column=1, sticky="ns")

        # Start extraction button
        self.extract_button = tk.Button(root, text="Start Realtime Extract", command=self.start_realtime_extract)
        self.extract_button.grid(row=1, column=0, pady=5)

        self.running = False
        self.seen_events = set()  # To store seen event IDs

    def start_realtime_extract(self):
        if not self.running:
            self.running = True
            self.extract_button.config(state=tk.DISABLED)
            threading.Thread(target=self.extract_logs, daemon=True).start()

    def extract_logs(self):
        # Define log sources to read from
        log_sources = ["System", "Application", "Security"]

        while self.running:
            for log_type in log_sources:
                try:
                    hand = win32evtlog.OpenEventLog("localhost", log_type)
                    events = win32evtlog.ReadEventLog(
                        hand,
                        win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                        0
                    )
                    if events:
                        for event in events:
                            if event.RecordNumber in self.seen_events:
                                continue

                            self.seen_events.add(event.RecordNumber)

                            time_generated = event.TimeGenerated.Format()
                            source = event.SourceName
                            level = self.get_event_level(event.EventType)
                            category = event.EventCategory
                            message = " ".join(event.StringInserts) if event.StringInserts else "No message"

                            self.log_tree.insert(
                                "", "end",
                                values=(time_generated, source, level, category, message)
                            )

                    # Scroll only if the scrollbar is at the bottom
                    self.auto_scroll()

                except Exception as e:
                    print(f"Error reading {log_type} log: {e}")
            time.sleep(5)  # Wait 5 seconds before next extraction

    def auto_scroll(self):
        """Scroll only if the scrollbar is near the bottom."""
        yview_position = self.log_tree.yview()
        if yview_position[1] >= 0.95:  # Scroll only if scrollbar is at 95% or closer to the bottom
            self.log_tree.yview_moveto(1.0)

    def get_event_level(self, event_type):
        """Map event type to level."""
        levels = {
            win32evtlog.EVENTLOG_ERROR_TYPE: "Error",
            win32evtlog.EVENTLOG_WARNING_TYPE: "Warning",
            win32evtlog.EVENTLOG_INFORMATION_TYPE: "Information",
            win32evtlog.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
            win32evtlog.EVENTLOG_AUDIT_FAILURE: "Audit Failure"
        }
        return levels.get(event_type, "Unknown")


# Run the app
if __name__ == "__main__":
    # Check if the script is running with administrative privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("This script requires administrative privileges to run.")
        exit(1)

    root = tk.Tk()
    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)
    app = EventViewerApp(root)
    root.mainloop()
