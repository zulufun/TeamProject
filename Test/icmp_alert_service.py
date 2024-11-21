import win32serviceutil
import win32service
import win32event
import time
import logging
import socket
import struct
import tkinter as tk
from threading import Thread

# Cấu hình logging
logging.basicConfig(
    filename='icmp_service.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
)

class ICMPAlertService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ICMPAlertService"  # Tên của service
    _svc_display_name_ = "ICMP Alert Service"  # Tên hiển thị trong Services
    _svc_description_ = "A Python service that alerts on ICMP packet detection."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        self.running = False
        win32event.SetEvent(self.stop_event)
        logging.info("Service is stopping...")
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        logging.info("Service is starting...")
        Thread(target=self.monitor_icmp).start()
        while self.running:
            time.sleep(1)  # Giữ service chạy
        logging.info("Service has stopped.")

    def monitor_icmp(self):
        """
        Lắng nghe các gói tin ICMP và hiển thị cảnh báo.
        """
        try:
            # Tạo socket để lắng nghe ICMP
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(1)  # Timeout để không treo service

            logging.info("ICMP monitoring started.")
            while self.running:
                try:
                    # Nhận gói tin
                    packet, addr = sock.recvfrom(1024)
                    self.handle_icmp_packet(packet, addr)
                except socket.timeout:
                    continue
        except Exception as e:
            logging.error(f"Error in ICMP monitoring: {e}")

    def handle_icmp_packet(self, packet, addr):
        """
        Xử lý gói tin ICMP và hiển thị thông báo.
        """
        ip_header = packet[:20]  # Header IP là 20 byte đầu
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)  # Giải mã header IP

        # Lấy loại ICMP từ phần dữ liệu
        icmp_header = packet[20:28]
        icmp_type, _, _, _, _ = struct.unpack('!BBHHH', icmp_header)

        if icmp_type == 8:  # Loại 8 là Echo Request (ping)
            src_ip = socket.inet_ntoa(iph[8])  # Lấy địa chỉ IP nguồn
            logging.info(f"ICMP Echo Request detected from {src_ip}")
            self.show_alert(f"ICMP Echo Request detected from {src_ip}")

    def show_alert(self, message):
        """
        Hiển thị thông báo popup.
        """
        def popup():
            root = tk.Tk()
            root.withdraw()  # Ẩn cửa sổ chính
            tk.messagebox.showinfo("ICMP Alert", message)
            root.destroy()

        Thread(target=popup).start()


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(ICMPAlertService)
