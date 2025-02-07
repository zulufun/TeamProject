import tkinter as tk
from tkinter import ttk
import win32evtlog
import threading
import time


# Placeholder for LLM model integration
def analyze_log_with_llm(log_content):
    """
    Fake LLM processing function.
    Replace this with an actual call to your LLM API or function.
    """
    response = {
        "summary": "The log indicates a network timeout error.",
        "causes": ["Network connectivity issues", "Firewall blocking connections"],
        "suggestions": ["Check network cables", "Verify firewall rules"]
    }
    return f"Analysis Result:\nSummary: {response['summary']}\nCauses: {', '.join(response['causes'])}\nSuggestions: {', '.join(response['suggestions'])}"


class ExtraFeatureWindow:
    def __init__(self, root):
        self.window = tk.Toplevel(root)  # Tạo cửa sổ mới
        self.window.title("Extra Feature - Log Analysis")

        # Configure layout
        self.window.rowconfigure(0, weight=1)
        self.window.columnconfigure(0, weight=3)  # Log list takes more space
        self.window.columnconfigure(1, weight=2)  # Analysis column

        # Log list (Treeview)
        self.log_tree = ttk.Treeview(
            self.window,
            columns=("Time", "Source", "Category", "Event ID", "Message", "Computer", "User SID"),
            show="headings",
            selectmode="browse"
        )
        self.log_tree.heading("Time", text="Time")
        self.log_tree.heading("Source", text="Source")
        self.log_tree.heading("Category", text="Category")
        self.log_tree.heading("Event ID", text="Event ID")
        self.log_tree.heading("Message", text="Message")
        self.log_tree.heading("Computer", text="Computer")
        self.log_tree.heading("User SID", text="User SID")
        self.log_tree.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # Scrollbar for Treeview
        tree_scrollbar = ttk.Scrollbar(self.window, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.grid(row=0, column=0, sticky="nse")

        # Bind event for selecting log
        self.log_tree.bind("<<TreeviewSelect>>", self.display_log_details)

        # Analysis display (Text widget)
        self.analysis_text = tk.Text(self.window, wrap=tk.WORD, state="normal")
        self.analysis_text.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        # Start extraction button
        self.extract_button = tk.Button(self.window, text="Start Realtime Extract", command=self.start_realtime_extract)
        self.extract_button.grid(row=1, column=0, columnspan=2, pady=5)

        self.running = False
        self.last_record_number = self.load_last_record_number()  # Load last processed record

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
                        category = win32evtlog.GetEventCategoryDescription(event.EventCategory, log_type) if event.EventCategory else "N/A"
                        event_id = event.EventID & 0xFFFF  # Ensure correct Event ID
                        message = " ".join(event.StringInserts) if event.StringInserts else "No message"
                        computer_name = event.ComputerName
                        user_sid = event.Sid if event.Sid else "N/A"

                        # Insert log into Treeview
                        item_id = self.log_tree.insert("", "end", values=(event_time, source, category, event_id, message, computer_name, user_sid))

                        # Auto-scroll to the latest log
                        self.log_tree.see(item_id)

                self.save_last_record_number()  # Save state after processing logs

            except Exception as e:
                print(f"Error reading event log: {e}")

            time.sleep(5)  # Check for new logs every 5 seconds

    def display_log_details(self, event):
        """Display log details and analysis in the analysis column."""
        selected_item = self.log_tree.selection()
        if selected_item:
            log_values = self.log_tree.item(selected_item, "values")
            log_content = f"""Time: {log_values[0]}
Source: {log_values[1]}
Category: {log_values[2]}
Event ID: {log_values[3]}
Message: {log_values[4]}
Computer: {log_values[5]}
User SID: {log_values[6]}"""

            # Analyze the log content with LLM
            analysis_result = analyze_log_with_llm(log_content)

            # Display in the analysis column
            self.analysis_text.config(state="normal")
            self.analysis_text.delete("1.0", tk.END)
            self.analysis_text.insert(tk.END, analysis_result)
            self.analysis_text.config(state="disabled")

    def save_last_record_number(self):
        with open("last_record.txt", "w") as f:
            f.write(str(self.last_record_number))

    def load_last_record_number(self):
        try:
            with open("last_record.txt", "r") as f:
                return int(f.read().strip())
        except FileNotFoundError:
            return 0  # Default value if no file exists


# Hàm này dùng để mở cửa sổ tính năng "Extra Feature"
def extra_future(root):
    ExtraFeatureWindow(root)


# Chương trình chính
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Main Program")

    # Nút mở cửa sổ "Extra Feature"
    extra_button = tk.Button(root, text="Open Extra Feature", command=lambda: extra_future(root))
    extra_button.pack(pady=20)

    root.mainloop()
