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
                response = requests.get(f'http://ip-api.com/json/{self.ip_address}').json()
                geo_data = {
                    'country': response.get('country', ''),
                    'city': response.get('city', ''),
                    'timezone': response.get('timezone', ''),
                    'lat': response.get('lat', ''),
                    'lon': response.get('lon', ''),
                    'isp': response.get('isp', '')
                }
                IPGeolocation.cache[self.ip_address] = geo_data
            except requests.RequestException:
                geo_data = {'country': '', 'city': '', 'timezone': '', 'lat': '', 'lon': '', 'isp': ''}

        self.country = geo_data['country']
        self.city = geo_data['city']
        self.time_zone = geo_data['timezone']
        self.latitude = geo_data['lat']
        self.longitude = geo_data['lon']
        self.isp = geo_data['isp']
