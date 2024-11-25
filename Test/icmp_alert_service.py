import win32serviceutil
import win32service
import win32event
import time
import logging
import socket
import threading
import tkinter as tk
from tkinter import messagebox
from queue import Queue
from pystray import Icon, Menu, MenuItem  # Thêm thư viện
from PIL import Image, ImageDraw  # Để tạo icon

# Cấu hình logging
logging.basicConfig(
    filename='icmp_service.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

class ICMPAlertService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ICMPAlertService"  # Tên của service
    _svc_display_name_ = "ICMP Alert Service"  # Tên hiển thị trong Services
    _svc_description_ = "A Python service that alerts on ICMP packet detection."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True
        self.queue = Queue()  # Hàng đợi để giao tiếp giữa luồng ICMP và GUI

        # Biến dành cho pystray
        self.icon = None

    def SvcStop(self):
        """
        Dừng service một cách an toàn.
        """
        self.running = False
        win32event.SetEvent(self.stop_event)
        if self.icon:
            self.icon.stop()  # Dừng biểu tượng pystray
        logging.info("Service is stopping...")
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        """
        Bắt đầu service và chạy các tác vụ chính.
        """
        logging.info("Service is starting...")

        try:
            # Khởi chạy pystray icon
            threading.Thread(target=self.run_tray_icon, daemon=True).start()

            # Chạy Tkinter trong một thread riêng
            tkinter_thread = threading.Thread(target=self.start_tkinter)
            tkinter_thread.daemon = True
            tkinter_thread.start()

            # Bắt đầu lắng nghe gói ICMP
            self.monitor_icmp()
        except Exception as e:
            logging.error(f"Service encountered an error: {e}")

        logging.info("Service has stopped.")

    def start_tkinter(self):
        """
        Khởi động Tkinter trong một luồng riêng để hiển thị thông báo.
        """
        root = tk.Tk()
        root.withdraw()  # Ẩn cửa sổ chính

        # Hàm kiểm tra hàng đợi và hiển thị popup
        def check_queue():
            while not self.queue.empty():
                src_ip = self.queue.get()
                messagebox.showinfo("ICMP Ping Alert", f"Ping received from {src_ip}")
            if self.running:
                root.after(100, check_queue)  # Kiểm tra hàng đợi mỗi 100ms

        root.after(100, check_queue)
        root.mainloop()

    def monitor_icmp(self):
        """
        Lắng nghe các gói tin ICMP và ghi log khi phát hiện.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(1)  # Timeout để tránh treo
            logging.info("ICMP monitoring started.")

            while self.running:
                try:
                    packet, addr = sock.recvfrom(1024)
                    src_ip = addr[0]  # Lấy địa chỉ IP nguồn
                    logging.info(f"Received ICMP packet from {src_ip}")
                    self.queue.put(src_ip)  # Gửi địa chỉ IP vào hàng đợi
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Error receiving packets: {e}")
        except Exception as e:
            logging.error(f"Failed to start ICMP monitoring: {e}")

    def run_tray_icon(self):
        """
        Tạo và chạy biểu tượng trong System Tray.
        """
        def quit_service(icon, item):
            self.SvcStop()

        # Tạo icon (vẽ một hình tròn màu xanh)
        image = Image.new("RGB", (64, 64), color=(0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.ellipse((16, 16, 48, 48), fill=(0, 255, 0))

        # Menu của system tray
        menu = Menu(
            MenuItem("Quit", quit_service)
        )

        # Tạo và chạy icon
        self.icon = Icon("ICMPAlertService", image, "ICMP Alert Service", menu)
        self.icon.run()

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(ICMPAlertService)
