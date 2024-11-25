import tkinter as tk
from tkinter import scrolledtext
import threading
import time
import win32evtlog  # Thư viện xử lý Event Viewer trên Windows


class LogMonitor:
    def __init__(self, frame):
        self.frame = frame
        self.log_text = scrolledtext.ScrolledText(frame, width=80, height=25)
        self.log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.start_log_button = tk.Button(frame, text="Start Log Monitoring", command=self.start_log_monitor)
        self.start_log_button.pack(side=tk.LEFT, padx=10)

        self.stop_log_button = tk.Button(frame, text="Stop Log Monitoring", command=self.stop_log_monitor)
        self.stop_log_button.pack(side=tk.LEFT, padx=10)
        self.stop_log_button['state'] = tk.DISABLED

        self.log_running = False

    def start_log_monitor(self):
        self.log_running = True
        self.stop_log_button['state'] = tk.NORMAL
        self.start_log_button['state'] = tk.DISABLED
        threading.Thread(target=self.monitor_logs, daemon=True).start()

    def stop_log_monitor(self):
        self.log_running = False
        self.start_log_button['state'] = tk.NORMAL
        self.stop_log_button['state'] = tk.DISABLED

    def monitor_logs(self):
        server = 'localhost'
        logtype = 'System'  # Thay đổi thành 'Application' hoặc 'Security'

        self.log_text.insert(tk.END, "Starting log monitoring...\n")
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while self.log_running:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if events:
                for event in events:
                    message = f"Time: {event.TimeGenerated}\nSource: {event.SourceName}\nEvent ID: {event.EventID}\n{'-' * 40}\n"
                    self.log_text.insert(tk.END, message)
                    self.log_text.see(tk.END)
            time.sleep(2)
