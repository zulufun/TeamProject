import tkinter as tk
from tkinter import ttk
import win32evtlog
import threading
import time


# Placeholder for LLM model integration
def analyze_log_with_llm(log_content):
    """Fake LLM processing function."""
    # Replace this with an actual call to your LLM API or function
    return f"Analyzed result for---> Xuất kết quả đọc log từ model:\n{log_content}"


class EventViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Event Viewer Log Extractor with Analysis")

        # Configure layout
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=3)  # Log list takes more space
        self.root.columnconfigure(1, weight=2)  # Analysis column

        # Log list (Treeview)
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

        # Bind event for selecting log
        self.log_tree.bind("<<TreeviewSelect>>", self.display_log_details)

        # Analysis display (ScrolledText)
        self.analysis_text = tk.Text(root, wrap=tk.WORD, state="normal")
        self.analysis_text.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        # Start extraction button
        self.extract_button = tk.Button(root, text="Start Realtime Extract", command=self.start_realtime_extract)
        self.extract_button.grid(row=1, column=0, columnspan=2, pady=5)

        self.running = False
        self.last_record_number = 0  # Track the last processed RecordNumber

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
            events = win32evtlog.ReadEventLog(
                hand,
                win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                0
            )
            if events:
                for event in events:
                    event_id = event.RecordNumber  # Unique identifier for each log

                    # Process only new logs
                    if event_id <= self.last_record_number:
                        continue

                    self.last_record_number = event_id  # Update the last processed record number
                    event_time = event.TimeGenerated.Format() if event.TimeGenerated else "N/A"
                    source = event.SourceName
                    category = event.EventCategory
                    message = " ".join(event.StringInserts) if event.StringInserts else "No message"

                    # Insert log into Treeview
                    item_id = self.log_tree.insert("", "end", values=(event_time, source, category, message))

                    # Auto-scroll to the latest log
                    self.log_tree.see(item_id)

            time.sleep(5)  # Check for new logs every 5 seconds

    def display_log_details(self, event):
        """Display log details and analysis in the analysis column."""
        selected_item = self.log_tree.selection()
        if selected_item:
            log_values = self.log_tree.item(selected_item, "values")
            log_content = f"Time: {log_values[0]}\nSource: {log_values[1]}\nCategory: {log_values[2]}\nMessage: {log_values[3]}"

            # Analyze the log content with LLM
            analysis_result = analyze_log_with_llm(log_content)

            # Display in the analysis column
            self.analysis_text.config(state="normal")
            self.analysis_text.delete("1.0", tk.END)
            self.analysis_text.insert(tk.END, analysis_result)
            self.analysis_text.config(state="disabled")


# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = EventViewerApp(root)
    root.mainloop()
