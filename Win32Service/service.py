import tkinter as tk
from tkinter import messagebox
import socket
import threading
import time
import smtplib
from email.mime.text import MIMEText

# Configuration
LOG_FILE = "tcp_trigger_log.txt"
MONITOR_PORT = 8080  # Port to monitor for incoming connections
EMAIL_NOTIFICATION = {
    "enabled": False,
    "sender": "your_email@example.com",
    "password": "your_email_password",
    "receiver": "receiver_email@example.com",
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
}

# Function to write logs
def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

# Function to send email notifications
def send_email_notification(message):
    if not EMAIL_NOTIFICATION["enabled"]:
        return
    try:
        msg = MIMEText(message)
        msg["Subject"] = "TCP Trigger Notification"
        msg["From"] = EMAIL_NOTIFICATION["sender"]
        msg["To"] = EMAIL_NOTIFICATION["receiver"]

        with smtplib.SMTP(EMAIL_NOTIFICATION["smtp_server"], EMAIL_NOTIFICATION["smtp_port"]) as server:
            server.starttls()
            server.login(EMAIL_NOTIFICATION["sender"], EMAIL_NOTIFICATION["password"])
            server.sendmail(
                EMAIL_NOTIFICATION["sender"],
                EMAIL_NOTIFICATION["receiver"],
                msg.as_string(),
            )
    except Exception as e:
        log_message(f"Failed to send email: {e}")

# Function to monitor incoming connections
def monitor_connections(port, ui_callback):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", port))
        server_socket.listen(5)
        log_message(f"Started monitoring on port {port}")

        while True:
            client_socket, client_address = server_socket.accept()
            client_ip, client_port = client_address
            message = f"Connection from {client_ip}:{client_port}"
            log_message(message)
            ui_callback(message)
            send_email_notification(message)
            client_socket.close()

# Tkinter UI class
class TcpTriggerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TCP Trigger Service")
        self.root.geometry("400x300")

        self.status_label = tk.Label(root, text="Service is running...", fg="green")
        self.status_label.pack(pady=10)

        self.log_text = tk.Text(root, height=15, width=50)
        self.log_text.pack()

        self.stop_button = tk.Button(root, text="Stop Service", command=self.stop_service)
        self.stop_button.pack(pady=10)

        self.monitor_thread = threading.Thread(
            target=monitor_connections, args=(MONITOR_PORT, self.display_alert)
        )
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def display_alert(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        messagebox.showinfo("TCP Trigger Alert", message)

    def stop_service(self):
        self.root.quit()

# Main function
if __name__ == "__main__":
    root = tk.Tk()
    app = TcpTriggerApp(root)
    root.mainloop()
