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
        # Tạo cửa sổ phụ từ cửa sổ chính
        self.network_monitor_window = tk.Toplevel(root_window)
        self.network_monitor_window.title("Detailed Local Network Monitor")
        self.network_monitor_window.geometry("800x500")

        # Định nghĩa các cột cho bảng hiển thị: Interface, IP Address, MAC Address, Vendor, Device Type
        self.table_columns = ("Interface", "IP Address", "MAC Address", "Vendor", "Device Type")
        self.device_table = ttk.Treeview(self.network_monitor_window, columns=self.table_columns, show="headings")
        for column_name in self.table_columns:
            self.device_table.heading(column_name, text=column_name)
            self.device_table.column(column_name, width=150, anchor="center")
        self.device_table.pack(fill="both", expand=True, padx=10, pady=10)

        # Tạo nút Refresh để làm mới danh sách thiết bị
        self.refresh_button = tk.Button(self.network_monitor_window, text="Refresh", command=self.refresh_device_list)
        self.refresh_button.pack(pady=5)

        # Bộ nhớ đệm (cache) cho kết quả tra cứu Vendor dựa trên địa chỉ MAC
        self.vendor_lookup_cache = {}

        # Khởi tạo asyncio event loop trong một thread riêng biệt để xử lý các tác vụ bất đồng bộ
        self.asyncio_event_loop = asyncio.new_event_loop()
        self.asyncio_event_loop_thread = threading.Thread(target=self.start_asyncio_event_loop, daemon=True)
        self.asyncio_event_loop_thread.start()

        # Khởi tạo thread để tự động làm mới danh sách thiết bị mỗi 10 giây
        self.auto_refresh_running = True
        self.auto_refresh_thread = threading.Thread(target=self.periodic_device_refresh, daemon=True)
        self.auto_refresh_thread.start()

        # Làm mới danh sách thiết bị ngay khi khởi chạy
        self.refresh_device_list()

        # Đăng ký sự kiện đóng cửa sổ: dừng các thread và dừng asyncio loop khi cửa sổ bị đóng
        self.network_monitor_window.protocol("WM_DELETE_WINDOW", self.handle_window_close)

    def start_asyncio_event_loop(self):
        """
        Hàm này chạy asyncio event loop trong một thread riêng biệt.
        """
        asyncio.set_event_loop(self.asyncio_event_loop)
        self.asyncio_event_loop.run_forever()

    def handle_window_close(self):
        """
        Xử lý sự kiện đóng cửa sổ:
          - Dừng thread tự động làm mới.
          - Dừng asyncio event loop.
          - Đóng cửa sổ.
        """
        self.auto_refresh_running = False
        self.asyncio_event_loop.call_soon_threadsafe(self.asyncio_event_loop.stop)
        self.network_monitor_window.destroy()

    def periodic_device_refresh(self):
        """
        Hàm này tự động làm mới danh sách thiết bị mỗi 10 giây.
        """
        while self.auto_refresh_running:
            time.sleep(10)
            # Sử dụng phương thức after để cập nhật giao diện một cách an toàn từ thread khác
            self.network_monitor_window.after(0, self.refresh_device_list)

    def refresh_device_list(self):
        """
        Hàm này lấy thông tin các thiết bị kết nối thông qua lệnh 'arp -a', sau đó:
          - Phân tích kết quả trả về và loại bỏ các mục trùng lặp dựa trên địa chỉ MAC.
          - Cập nhật bảng Treeview với thông tin tạm thời ("Loading...") cho các cột Vendor và Device Type.
          - Gọi tác vụ tra cứu vendor bất đồng bộ cho từng thiết bị.
        """
        try:
            arp_output = subprocess.check_output(["arp", "-a"], universal_newlines=True)
        except Exception as error_exception:
            print("Error executing arp command:", error_exception)
            arp_output = ""

        # Phân tích kết quả từ lệnh arp và loại bỏ các thiết bị trùng lặp (dựa trên địa chỉ MAC)
        device_list = self.parse_arp_output_results(arp_output)

        # Xóa toàn bộ dữ liệu cũ trong bảng Treeview
        for table_item in self.device_table.get_children():
            self.device_table.delete(table_item)

        # Chèn các dòng mới vào bảng với thông tin tạm thời "Loading..." cho Vendor và Device Type
        table_item_identifiers = []
        for device_info in device_list:
            item_identifier = self.device_table.insert("", "end", values=(
                device_info["interface"],
                device_info["ip"],
                device_info["mac"],
                "Loading...",  # Sẽ cập nhật sau khi tra cứu Vendor
                "Loading..."  # Sẽ cập nhật sau khi phân loại thiết bị
            ))
            table_item_identifiers.append(item_identifier)

        # Gọi hàm bất đồng bộ để tra cứu Vendor cho từng thiết bị theo thứ tự (tuần tự) nhằm giảm độ trễ
        asyncio.run_coroutine_threadsafe(
            self.update_vendor_information(device_list, table_item_identifiers),
            self.asyncio_event_loop
        )

    async def update_vendor_information(self, device_list, table_item_identifiers):
        """
        Hàm bất đồng bộ duyệt qua danh sách các thiết bị, với mỗi thiết bị:
          - Tra cứu Vendor dựa trên địa chỉ MAC.
          - Phân loại thiết bị (Device Type) dựa trên thông tin Vendor.
          - Cập nhật kết quả lên bảng Treeview.
        """
        for device_info, item_identifier in zip(device_list, table_item_identifiers):
            mac_address = device_info["mac"]
            vendor_result = await self.lookup_vendor_asynchronously(mac_address)
            device_type_result = self.determine_device_type(vendor_result)
            # Cập nhật giao diện từ thread chính bằng phương thức after
            self.network_monitor_window.after(0, self.update_table_item, item_identifier, vendor_result,
                                              device_type_result)

    def update_table_item(self, item_identifier, vendor_value, device_type_value):
        """
        Cập nhật thông tin Vendor và Device Type cho một dòng trong bảng Treeview.
        """
        self.device_table.set(item_identifier, "Vendor", vendor_value)
        self.device_table.set(item_identifier, "Device Type", device_type_value)

    async def lookup_vendor_asynchronously(self, mac_address):
        """
        Tra cứu tên nhà sản xuất (Vendor) dựa trên địa chỉ MAC sử dụng aiohttp và API tại https://api.macvendors.com.
        Sử dụng cache để tránh gọi API nhiều lần cho cùng một MAC.
        """
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
        except Exception as exception_error:
            vendor_name = "Unknown"

        self.vendor_lookup_cache[mac_address] = vendor_name
        return vendor_name

    def determine_device_type(self, vendor_name):
        """
        Phân loại thiết bị dựa trên thông tin Vendor.
          - Nếu Vendor chứa từ khóa chỉ ra thiết bị di động (ví dụ: iPhone, Samsung, ...),
            trả về "Phone".
          - Nếu không, trả về "Computer".
          - Nếu thông tin Vendor không có hoặc không xác định, trả về "Unknown".
        """
        if vendor_name == "Unknown" or vendor_name == "":
            return "Unknown"
        # Danh sách các từ khóa gợi ý rằng thiết bị có thể là điện thoại
        mobile_device_keywords = [
            "iPhone", "Samsung", "Huawei", "Xiaomi", "LG",
            "HTC", "Sony", "OnePlus", "Nokia", "Motorola"
        ]
        for keyword in mobile_device_keywords:
            if keyword.lower() in vendor_name.lower():
                return "Phone"
        return "Computer"

    def parse_arp_output_results(self, arp_command_output):
        """
        Phân tích kết quả đầu ra của lệnh 'arp -a' và loại bỏ các mục trùng lặp dựa trên địa chỉ MAC.
        Hỗ trợ định dạng trên cả hệ thống Windows và Linux.

        Ví dụ đầu ra của lệnh arp -a:
          - Windows: "  192.168.1.1           00-11-22-33-44-55     dynamic"
          - Linux:   "? (192.168.1.1) at 00:11:22:33:44:55 [ether] on en0"
        """
        unique_devices = {}
        current_network_interface = "Unknown"
        for output_line in arp_command_output.splitlines():
            # Kiểm tra dòng chứa thông tin giao diện mạng (trên Windows)
            interface_match = re.search(r"Interface:\s+(\d{1,3}(?:\.\d{1,3}){3})", output_line)
            if interface_match:
                current_network_interface = interface_match.group(1)
                continue

            # Xử lý định dạng kết quả trên hệ thống Windows
            windows_format_match = re.search(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+(([0-9a-fA-F]{2}(?:[-:])){5}[0-9a-fA-F]{2})",
                output_line
            )
            if windows_format_match:
                ip_address = windows_format_match.group(1)
                mac_address = windows_format_match.group(2).replace('-', ':')
                if mac_address not in unique_devices:
                    unique_devices[mac_address] = {
                        "interface": current_network_interface,
                        "ip": ip_address,
                        "mac": mac_address
                    }
                continue

            # Xử lý định dạng kết quả trên hệ thống Linux
            linux_format_match = re.search(
                r"\? \((\d{1,3}(?:\.\d{1,3}){3})\) at ([0-9a-fA-F:]{17}) .* on (\S+)",
                output_line
            )
            if linux_format_match:
                ip_address = linux_format_match.group(1)
                mac_address = linux_format_match.group(2)
                network_interface = linux_format_match.group(3)
                if mac_address not in unique_devices:
                    unique_devices[mac_address] = {
                        "interface": network_interface,
                        "ip": ip_address,
                        "mac": mac_address
                    }
        # Trả về danh sách các thiết bị duy nhất (không có trùng lặp theo MAC)
        return list(unique_devices.values())


def open_detailed_network_monitor_window(root_window):
    """
    Hàm này khởi tạo cửa sổ theo dõi mạng nội bộ chi tiết.
    """
    DetailedLocalNetworkMonitorWindow(root_window)


# Chương trình chính
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
