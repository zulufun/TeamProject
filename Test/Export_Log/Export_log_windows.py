import tkinter as tk
from tkinter import scrolledtext
import win32evtlog
import threading
import time


class EventViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Event Viewer Log Extractor")

        # Scrolled Text for displaying logs
        self.log_display = scrolledtext.ScrolledText(root, width=100, height=30, wrap=tk.WORD)
        self.log_display.pack(pady=10, padx=10)

        # Button to start extracting logs
        self.extract_button = tk.Button(root, text="Start Realtime Extract", command=self.start_realtime_extract)
        self.extract_button.pack(pady=5)

        self.running = False
        self.seen_events = set()  # To store seen event IDs

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
            events = win32evtlog.ReadEventLog(hand,
                                              win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                                              0)
            if events:
                for event in events:
                    event_id = event.RecordNumber  # Unique identifier for each log
                    if event_id in self.seen_events:
                        continue  # Skip already processed logs

                    self.seen_events.add(event_id)
                    event_time = event.TimeGenerated.Format() if event.TimeGenerated else "N/A"
                    source = event.SourceName
                    category = event.EventCategory
                    message = event.StringInserts if event.StringInserts else ["No message"]

                    log_entry = f"Time: {event_time}\nSource: {source}\nCategory: {category}\nMessage: {' '.join(message)}\n{'-' * 80}\n"

                    # Update UI in the main thread
                    self.root.after(0, self.log_display.insert, tk.END, log_entry)
                    self.root.after(0, self.log_display.see, tk.END)  # Auto-scroll to the latest log

            time.sleep(5)  # Check for new logs every 5 seconds


# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = EventViewerApp(root)
    root.mainloop()
# Phần này sẽ lấy log mới trước sau đó sẽ req lại nhiều ần để lấy log càng ngày càng cũ hơn