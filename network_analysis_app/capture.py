import pyshark


class PacketCapture:
    def __init__(self, interface):
        self.interface = interface
        self.capture = None

    def sniff_continuously(self):
        self.capture = pyshark.LiveCapture(interface=self.interface)
        return self.capture.sniff_continuously()

    def close(self):
        if self.capture:
            self.capture.close()