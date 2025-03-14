import tkinter as tk
from tkinter import ttk
import subprocess
import re
import threading
import time
import asyncio
import aiohttp


class DetailedLocalNetworkMonitorWindow:
    """
    Lớp này tạo một cửa sổ phụ hiển thị danh sách các thiết bị được kết nối trong mạng nội bộ.
    Mỗi thiết bị được hiển thị với các thông tin:
      - Interface: Giao diện mạng mà thiết bị được phát hiện.
      - IP Address: Địa chỉ IP của thiết bị.
      - MAC Address: Địa chỉ MAC (độc nhất cho mỗi thiết bị).
      - Vendor: Tên nhà sản xuất của thiết bị (tra cứu thông qua API).
      - Device Type: Phân loại thiết bị (ví dụ: Phone hay Computer) dựa trên thông tin Vendor.

    Chức năng tra cứu vendor được thực hiện bất đồng bộ bằng aiohttp, và kết quả được cập nhật tuần tự
    nhằm tránh lag giao diện khi tốc độ mạng chậm.
    """

    def __init__(self, root_window):
        self.network_monitor_window = tk.Toplevel(root_window)
        self.network_monitor_window.title("Detailed Local Network Monitor")
        self.network_monitor_window.geometry("800x500")

        # Định nghĩa các cột cho bảng hiển thị
        self.table_columns = ("Interface", "IP Address", "MAC Address", "Vendor", "Device Type")
        self.device_table = ttk.Treeview(self.network_monitor_window, columns=self.table_columns, show="headings")
        for column_name in self.table_columns:
            self.device_table.heading(column_name, text=column_name)
            self.device_table.column(column_name, width=150, anchor="center")
        self.device_table.pack(fill="both", expand=True, padx=10, pady=10)

        # Nút Refresh để làm mới danh sách thiết bị
        self.refresh_button = tk.Button(self.network_monitor_window, text="Refresh", command=self.refresh_device_list)
        self.refresh_button.pack(pady=5)

        # Bộ nhớ đệm cho kết quả tra cứu Vendor
        self.vendor_lookup_cache = {}

        # Khởi tạo asyncio event loop trong một thread riêng để xử lý tác vụ bất đồng bộ
        self.asyncio_event_loop = asyncio.new_event_loop()
        self.asyncio_event_loop_thread = threading.Thread(target=self.start_asyncio_event_loop, daemon=True)
        self.asyncio_event_loop_thread.start()

        # Thread tự động làm mới danh sách thiết bị mỗi 10 giây
        self.auto_refresh_running = True
        self.auto_refresh_thread = threading.Thread(target=self.periodic_device_refresh, daemon=True)
        self.auto_refresh_thread.start()

        # Làm mới danh sách ngay khi khởi chạy
        self.refresh_device_list()

        # Lưu id của callback after để có thể hủy sau này
        self.after_id = None

        # Đăng ký sự kiện đóng cửa sổ: dừng các thread và event loop khi cửa sổ đóng
        self.network_monitor_window.protocol("WM_DELETE_WINDOW", self.handle_window_close)

    def start_asyncio_event_loop(self):
        asyncio.set_event_loop(self.asyncio_event_loop)
        self.asyncio_event_loop.run_forever()

    def handle_window_close(self):
        # Dừng thread tự động refresh và hủy callback after nếu có
        self.auto_refresh_running = False
        if self.after_id is not None:
            try:
                self.network_monitor_window.after_cancel(self.after_id)
            except tk.TclError:
                pass
        # Dừng asyncio loop
        self.asyncio_event_loop.call_soon_threadsafe(self.asyncio_event_loop.stop)
        self.network_monitor_window.destroy()

    def periodic_device_refresh(self):
        while self.auto_refresh_running:
            time.sleep(10)
            try:
                if self.network_monitor_window.winfo_exists() and self.device_table.winfo_exists():
                    self.after_id = self.network_monitor_window.after(0, self.refresh_device_list)
            except tk.TclError:
                break

    def refresh_device_list(self):
        # Kiểm tra xem device_table còn tồn tại không
        if not self.device_table.winfo_exists():
            return
        try:
            arp_output = subprocess.check_output(["arp", "-a"], universal_newlines=True)
        except Exception as error_exception:
            print("Error executing arp command:", error_exception)
            arp_output = ""

        # Phân tích kết quả của lệnh arp
        device_list = self.parse_arp_output_results(arp_output)

        # Xóa toàn bộ dữ liệu cũ trong bảng Treeview
        for table_item in self.device_table.get_children():
            try:
                self.device_table.delete(table_item)
            except tk.TclError:
                continue

        # Chèn các dòng mới vào bảng với giá trị tạm thời cho Vendor và Device Type
        table_item_identifiers = []
        for device_info in device_list:
            try:
                item_identifier = self.device_table.insert("", "end", values=(
                    device_info["interface"],
                    device_info["ip"],
                    device_info["mac"],
                    "Loading...",  # Vendor tạm thời
                    "Loading..."  # Device Type tạm thời
                ))
                table_item_identifiers.append(item_identifier)
            except tk.TclError as e:
                print("TclError inserting row:", e)
                continue

        try:
            asyncio.run_coroutine_threadsafe(
                self.update_vendor_information(device_list, table_item_identifiers),
                self.asyncio_event_loop
            )
        except Exception as e:
            print("Error scheduling vendor update:", e)

    async def update_vendor_information(self, device_list, table_item_identifiers):
        for device_info, item_identifier in zip(device_list, table_item_identifiers):
            mac_address = device_info["mac"]
            vendor_result = await self.lookup_vendor_asynchronously(mac_address)
            device_type_result = self.determine_device_type(vendor_result)
            # Cập nhật thông tin lên bảng từ main thread
            self.network_monitor_window.after(0, self.update_table_item, item_identifier, vendor_result,
                                              device_type_result)

    def update_table_item(self, item_identifier, vendor_value, device_type_value):
        if not self.device_table.winfo_exists():
            return
        try:
            self.device_table.set(item_identifier, "Vendor", vendor_value)
            self.device_table.set(item_identifier, "Device Type", device_type_value)
        except tk.TclError as e:
            print("TclError in update_table_item:", e)

    async def lookup_vendor_asynchronously(self, mac_address):
        if mac_address in self.vendor_lookup_cache:
            return self.vendor_lookup_cache[mac_address]

        api_url = f"https://api.macvendors.com/{mac_address}"
        vendor_name = "Unknown"
        try:
            client_timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.get(api_url) as response:
                    if response.status == 200:
                        vendor_name = await response.text()
                    else:
                        vendor_name = "Unknown"
        except Exception:
            vendor_name = "Unknown"

        self.vendor_lookup_cache[mac_address] = vendor_name
        return vendor_name

    def determine_device_type(self, vendor_name):
        if vendor_name == "Unknown" or vendor_name == "":
            return "Unknown"
        mobile_device_keywords = ["iPhone", "Samsung", "Huawei", "Xiaomi", "LG", "HTC", "Sony", "OnePlus", "Nokia",
                                  "Motorola"]
        for keyword in mobile_device_keywords:
            if keyword.lower() in vendor_name.lower():
                return "Phone"
        return "Computer"

    def parse_arp_output_results(self, arp_command_output):
        unique_devices = {}
        current_network_interface = "Unknown"
        for output_line in arp_command_output.splitlines():
            # Kiểm tra dòng chứa thông tin giao diện (trên Windows)
            interface_match = re.search(r"Interface:\s+(\d{1,3}(?:\.\d{1,3}){3})", output_line)
            if interface_match:
                current_network_interface = interface_match.group(1)
                continue
            # Xử lý định dạng Windows
            windows_format_match = re.search(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+(([0-9a-fA-F]{2}(?:[-:])){5}[0-9a-fA-F]{2})",
                output_line
            )
            if windows_format_match:
                ip_address = windows_format_match.group(1)
                mac_address = windows_format_match.group(2).replace('-', ':')
                if mac_address not in unique_devices:
                    unique_devices[mac_address] = {"interface": current_network_interface, "ip": ip_address,
                                                   "mac": mac_address}
                continue
            # Xử lý định dạng Linux
            linux_format_match = re.search(
                r"\? \((\d{1,3}(?:\.\d{1,3}){3})\) at ([0-9a-fA-F:]{17}) .* on (\S+)",
                output_line
            )
            if linux_format_match:
                ip_address = linux_format_match.group(1)
                mac_address = linux_format_match.group(2)
                network_interface = linux_format_match.group(3)
                if mac_address not in unique_devices:
                    unique_devices[mac_address] = {"interface": network_interface, "ip": ip_address, "mac": mac_address}
        return list(unique_devices.values())


def open_detailed_network_monitor_window(root_window):
    DetailedLocalNetworkMonitorWindow(root_window)


if __name__ == "__main__":
    main_window = tk.Tk()
    main_window.title("Main Program")
    main_window.geometry("300x150")
    open_monitor_button = tk.Button(
        main_window,
        text="Open Detailed Network Monitor",
        command=lambda: open_detailed_network_monitor_window(main_window)
    )
    open_monitor_button.pack(pady=40)
    main_window.mainloop()
