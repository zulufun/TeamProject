import win32serviceutil
import win32service
import win32event
import time
import logging
import socket
import struct
import threading
import tkinter as tk
from tkinter import messagebox
from queue import Queue

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

    def SvcStop(self):
        """
        Dừng service một cách an toàn.
        """
        self.running = False
        win32event.SetEvent(self.stop_event)
        logging.info("Service is stopping...")
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        """
        Bắt đầu service và chạy các tác vụ chính.
        """
        logging.info("Service is starting...")
        print("Service is starting...")  # In ra màn hình để kiểm tra

        try:
            # Chạy Tkinter trong một thread riêng
            tkinter_thread = threading.Thread(target=self.start_tkinter)
            tkinter_thread.daemon = True
            tkinter_thread.start()

            # Bắt đầu lắng nghe gói ICMP
            self.monitor_icmp()
        except Exception as e:
            logging.error(f"Service encountered an error: {e}")
            print(f"Error in service: {e}")  # In ra màn hình để kiểm tra
        logging.info("Service has stopped.")
        print("Service has stopped.")  # In ra màn hình

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
            # Tạo socket RAW để lắng nghe ICMP
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(1)  # Timeout để tránh treo
            logging.info("ICMP monitoring started.")
            print("ICMP monitoring started...")  # Debug thông báo bắt đầu

            while self.running:
                try:
                    # Nhận gói tin ICMP
                    packet, addr = sock.recvfrom(1024)
                    src_ip = addr[0]  # Lấy địa chỉ IP nguồn
                    logging.info(f"Received ICMP packet from {src_ip}")
                    print(f"Received ICMP packet from {src_ip}")  # Debug

                    # Gửi địa chỉ IP vào hàng đợi để hiển thị popup
                    self.queue.put(src_ip)

                except socket.timeout:
                    # Kiểm tra địa chỉ localhost thủ công (127.0.0.1)
                    self.check_local_ping()
                except Exception as e:
                    logging.error(f"Error receiving packets: {e}")
                    print(f"Error receiving packets: {e}")
        except Exception as e:
            logging.error(f"Failed to start ICMP monitoring: {e}")
            print(f"Failed to start ICMP monitoring: {e}")

    def check_local_ping(self):
        """
        Kiểm tra và xử lý gói tin ICMP từ localhost (127.0.0.1).
        """
        try:
            # Sử dụng socket UDP để kiểm tra ping tới localhost
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_sock.connect(("127.0.0.1", 1))  # Kết nối tới localhost
            src_ip = test_sock.getsockname()[0]  # Lấy địa chỉ IP nguồn (127.0.0.1)
            test_sock.close()

            logging.info(f"Ping from localhost detected: {src_ip}")
            print(f"Ping from localhost detected: {src_ip}")  # Debug
            self.queue.put(src_ip)  # Gửi địa chỉ IP vào hàng đợi
        except Exception as e:
            logging.error(f"Error checking localhost ping: {e}")
            print(f"Error checking localhost ping: {e}")  # Debug

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(ICMPAlertService)
