##
    # def show_source_country_stats(self):
    #     self.stats_thread = threading.Thread(target=self.generate_source_country_stats)
    #     self.stats_thread.start()
    #
    # def show_source_service_stats(self):
    #     self.stats_thread = threading.Thread(target=self.generate_source_service_stats)
    #     self.stats_thread.start()
    #
    # def generate_source_country_stats(self):
    #     src_country_count = {}
    #     for packet in self.packet_list:
    #         if 'ip' in packet:
    #             source_ip = packet.ip.src
    #             source_geo = IPGeolocation(source_ip)
    #             src_country = source_geo.country
    #
    #             if src_country:
    #                 if src_country in src_country_count:
    #                     src_country_count[src_country] += 1
    #                 else:
    #                     src_country_count[src_country] = 1
    #
    #     self.master.after(0, self.plot_pie_chart, src_country_count, "Source Country Distribution")
    #
    # def generate_source_service_stats(self):
    #     src_service_count = {}
    #
    #     for packet in self.packet_list:
    #         if 'ip' in packet:
    #             source_ip = packet.ip.src
    #             source_geo = IPGeolocation(source_ip)
    #             src_service = source_geo.isp
    #
    #             if src_service:
    #                 if src_service in src_service_count:
    #                     src_service_count[src_service] += 1
    #                 else:
    #                     src_service_count[src_service] = 1
    #
    #     self.master.after(0, self.plot_pie_chart, src_service_count, "Source Service Distribution")
    #
    # def plot_pie_chart(self, data, title):
    #     labels = list(data.keys())
    #     sizes = list(data.values())
    #     plt.figure(figsize=(10, 6))
    #     plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    #     plt.title(title)
    #     plt.axis('equal')
    #     plt.show()