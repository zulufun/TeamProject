import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import win32evtlog
import threading
import asyncio
import aiohttp
import time

# Hàm phân tích log bằng LLM (bất đồng bộ)
async def analyze_log_with_llm_async(log_content):
    """
    Gửi log đến LLM Studio tại localhost:1234 và nhận kết quả trả về theo định dạng JSON.
    """
    try:
        url = "http://localhost:1234/analyze"
        headers = {"Content-Type": "application/json"}
        payload = {
            "prompt": f"""
            Hãy phân tích đoạn log dưới đây và trả về một output theo cấu trúc JSON với hai trường:

            warning: Boolean, giá trị là true nếu log có chứa lỗi hoặc cảnh báo, và false nếu không có vấn đề gì.
            discussion: Chuỗi mô tả chi tiết về ý nghĩa của log, viết bằng tiếng Việt, giải thích trạng thái hoặc lý do cảnh báo nếu có.

            Log:
            {log_content}
            """
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    return f"Analysis Result:\nWarning: {result['warning']}\nDiscussion: {result['discussion']}"
                else:
                    return f"Error: Received status code {response.status} from LLM Studio."
    except Exception as e:
        return f"Error during LLM analysis: {e}"

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
        tree_scrollbar.grid(row=0, column=0, sticky="nse")

        # Bind event for selecting log
        self.log_tree.bind("<<TreeviewSelect>>", self.on_log_select)

        # Analysis display (ScrolledText)
        self.analysis_text = tk.Text(root, wrap=tk.WORD, state="normal")
        self.analysis_text.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        # Start extraction button
        self.extract_button = tk.Button(root, text="Start Realtime Extract", command=self.start_realtime_extract)
        self.extract_button.grid(row=1, column=0, columnspan=2, pady=5)

        self.running = False
        self.seen_events = set()  # To track processed events

    def start_realtime_extract(self):
        if not self.running:
            self.running = True
            self.extract_button.config(state=tk.DISABLED)
            threading.Thread(target=self.extract_logs, daemon=True).start()

    def extract_logs(self):
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
                except Exception as e:
                    print(f"Error reading {log_type} log: {e}")
            time.sleep(5)  # Wait 5 seconds before next extraction

    def get_event_level(self, event_type):
        levels = {
            win32evtlog.EVENTLOG_ERROR_TYPE: "Error",
            win32evtlog.EVENTLOG_WARNING_TYPE: "Warning",
            win32evtlog.EVENTLOG_INFORMATION_TYPE: "Information",
            win32evtlog.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
            win32evtlog.EVENTLOG_AUDIT_FAILURE: "Audit Failure"
        }
        return levels.get(event_type, "Unknown")

    def on_log_select(self, event):
        """Display log details and analysis in the analysis column."""
        selected_item = self.log_tree.selection()
        if selected_item:
            log_values = self.log_tree.item(selected_item, "values")
            log_content = f"""Time: {log_values[0]}
Source: {log_values[1]}
Level: {log_values[2]}
Category: {log_values[3]}
Message: {log_values[4]}"""

            # Hiển thị loading
            self.analysis_text.config(state="normal")
            self.analysis_text.delete("1.0", tk.END)
            self.analysis_text.insert(tk.END, "Đang phân tích log... Vui lòng chờ.\n")
            self.analysis_text.config(state="disabled")

            # Chạy phân tích log bất đồng bộ
            threading.Thread(target=self.analyze_log_in_background, args=(log_content,), daemon=True).start()

    def analyze_log_in_background(self, log_content):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        analysis_result = loop.run_until_complete(analyze_log_with_llm_async(log_content))

        # Cập nhật giao diện với kết quả
        self.analysis_text.config(state="normal")
        self.analysis_text.delete("1.0", tk.END)
        self.analysis_text.insert(tk.END, analysis_result)
        self.analysis_text.config(state="disabled")


# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = EventViewerApp(root)
    root.mainloop()
