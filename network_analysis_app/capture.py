import asyncio
import pyshark
import threading

class PacketCapture:
    def __init__(self, app):
        self.app = app
        self.running = False
        self.packet_list = []

    def start_capture(self, interface):
        self.running = True
        threading.Thread(target=self._capture_packets, args=(interface,)).start()

    def _capture_packets(self, interface):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        capture = pyshark.LiveCapture(interface=interface)

        for packet in capture.sniff_continuously():
            if not self.running:
                break
            self.packet_list.append(packet)
            self.app.display_packet(packet)
        loop.close()

    def stop_capture(self):
        self.running = False
