# import requests
# class IPGeolocation:
#     cache = {}
#
#     def __init__(self, ip_address):
#         self.latitude = ''
#         self.longitude = ''
#         self.country = ''
#         self.city = ''
#         self.time_zone = ''
#         self.isp = ''
#         self.ip_address = ip_address
#         self.get_location()
#
#     def get_location(self):
#         if self.ip_address in IPGeolocation.cache:
#             geo_data = IPGeolocation.cache[self.ip_address]
#         else:
#             try:
#                 json_request = requests.get(f'http://ip-api.com/json/{self.ip_address}').json()
#                 geo_data = {
#                     'country': json_request.get('country', ''),
#                     'city': json_request.get('city', ''),
#                     'timezone': json_request.get('timezone', ''),
#                     'lat': json_request.get('lat', ''),
#                     'lon': json_request.get('lon', ''),
#                     'isp': json_request.get('isp', '')
#                 }
#                 IPGeolocation.cache[self.ip_address] = geo_data
#             except requests.RequestException as e:
#                 print(f"Error fetching geolocation data: {e}")
#                 geo_data = {
#                     'country': '',
#                     'city': '',
#                     'timezone': '',
#                     'lat': '',
#                     'lon': '',
#                     'isp': ''
#                 }
#
#         self.country = geo_data['country']
#         self.city = geo_data['city']
#         self.time_zone = geo_data['timezone']
#         self.latitude = geo_data['lat']
#         self.longitude = geo_data['lon']
#         self.isp = geo_data['isp']
##########################################
import requests
import threading

class IPGeolocation:
    cache = {}

    def __init__(self, ip_address, callback=None):
        self.ip_address = ip_address
        # Ban đầu, các trường được đặt là "Loading"
        self.country = "Loading"
        self.city = "Loading"
        self.time_zone = "Loading"
        self.latitude = "Loading"
        self.longitude = "Loading"
        self.isp = "Loading"
        self.callback = callback
        # Chạy thread để lấy dữ liệu bất đồng bộ
        threading.Thread(target=self.get_location, daemon=True).start()

    def get_location(self):
        if self.ip_address in IPGeolocation.cache:
            geo_data = IPGeolocation.cache[self.ip_address]
        else:
            try:
                response = requests.get(f'http://ip-api.com/json/{self.ip_address}', timeout=5)
                json_request = response.json()
                geo_data = {
                    'country': json_request.get('country', 'Unknown'),
                    'city': json_request.get('city', 'Unknown'),
                    'timezone': json_request.get('timezone', 'Unknown'),
                    'lat': json_request.get('lat', 'Unknown'),
                    'lon': json_request.get('lon', 'Unknown'),
                    'isp': json_request.get('isp', 'Unknown')
                }
                IPGeolocation.cache[self.ip_address] = geo_data
            except requests.RequestException as e:
                print(f"Error fetching geolocation data for {self.ip_address}: {e}")
                geo_data = {
                    'country': 'Unknown',
                    'city': 'Unknown',
                    'timezone': 'Unknown',
                    'lat': 'Unknown',
                    'lon': 'Unknown',
                    'isp': 'Unknown'
                }
        # Cập nhật các thuộc tính
        self.country = geo_data['country']
        self.city = geo_data['city']
        self.time_zone = geo_data['timezone']
        self.latitude = geo_data['lat']
        self.longitude = geo_data['lon']
        self.isp = geo_data['isp']
        # Nếu có callback, gọi nó với self
        if self.callback:
            self.callback(self)
