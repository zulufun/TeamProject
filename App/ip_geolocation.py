import requests
class IPGeolocation:
    cache = {}

    def __init__(self, ip_address):
        self.latitude = ''
        self.longitude = ''
        self.country = ''
        self.city = ''
        self.time_zone = ''
        self.isp = ''
        self.ip_address = ip_address
        self.get_location()

    def get_location(self):
        if self.ip_address in IPGeolocation.cache:
            geo_data = IPGeolocation.cache[self.ip_address]
        else:
            try:
                json_request = requests.get(f'http://ip-api.com/json/{self.ip_address}').json()
                geo_data = {
                    'country': json_request.get('country', ''),
                    'city': json_request.get('city', ''),
                    'timezone': json_request.get('timezone', ''),
                    'lat': json_request.get('lat', ''),
                    'lon': json_request.get('lon', ''),
                    'isp': json_request.get('isp', '')
                }
                IPGeolocation.cache[self.ip_address] = geo_data
            except requests.RequestException as e:
                print(f"Error fetching geolocation data: {e}")
                geo_data = {
                    'country': '',
                    'city': '',
                    'timezone': '',
                    'lat': '',
                    'lon': '',
                    'isp': ''
                }

        self.country = geo_data['country']
        self.city = geo_data['city']
        self.time_zone = geo_data['timezone']
        self.latitude = geo_data['lat']
        self.longitude = geo_data['lon']
        self.isp = geo_data['isp']
