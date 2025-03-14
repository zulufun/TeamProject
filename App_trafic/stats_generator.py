# stats_generator.py

import threading
import matplotlib.pyplot as plt
# Giả sử IPGeolocation được định nghĩa ở một module khác,
# bạn cần import nó (hoặc thay thế bằng hàm, class phù hợp)
# from ip_geolocation import IPGeolocation
from ip_geolocation import IPGeolocation

class StatsGenerator:
    def __init__(self, master, packet_list):
        """
        :param master: Một widget của tkinter, dùng để gọi phương thức after
        :param packet_list: Danh sách các gói tin cần phân tích
        """
        self.master = master
        self.packet_list = packet_list
        self.stats_thread = None

    def show_source_country_stats(self):
        """Khởi chạy luồng để tính toán và hiển thị thống kê quốc gia nguồn."""
        self.stats_thread = threading.Thread(target=self.generate_source_country_stats)
        self.stats_thread.start()

    def show_source_service_stats(self):
        """Khởi chạy luồng để tính toán và hiển thị thống kê dịch vụ nguồn."""
        self.stats_thread = threading.Thread(target=self.generate_source_service_stats)
        self.stats_thread.start()

    def generate_source_country_stats(self):
        """Tính toán số lượng gói tin theo quốc gia nguồn."""
        src_country_count = {}
        for packet in self.packet_list:
            if 'ip' in packet:
                source_ip = packet.ip.src
                source_geo = IPGeolocation(source_ip)
                src_country = source_geo.country

                if src_country:
                    src_country_count[src_country] = src_country_count.get(src_country, 0) + 1

        # Dùng master.after để đảm bảo việc vẽ đồ thị chạy trên main thread của tkinter
        self.master.after(0, self.plot_pie_chart, src_country_count, "Source Country Distribution")

    def generate_source_service_stats(self):
        """Tính toán số lượng gói tin theo dịch vụ (ISP) nguồn."""
        src_service_count = {}
        for packet in self.packet_list:
            if 'ip' in packet:
                source_ip = packet.ip.src
                source_geo = IPGeolocation(source_ip)
                src_service = source_geo.isp

                if src_service:
                    src_service_count[src_service] = src_service_count.get(src_service, 0) + 1

        self.master.after(0, self.plot_pie_chart, src_service_count, "Source Service Distribution")

    def plot_pie_chart(self, data, title):
        """Vẽ biểu đồ tròn dựa trên dữ liệu và tiêu đề được cung cấp."""
        labels = list(data.keys())
        sizes = list(data.values())
        plt.figure(figsize=(10, 6))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title(title)
        plt.axis('equal')
        plt.show()
