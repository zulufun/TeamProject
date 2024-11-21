import win32serviceutil
import win32service
import win32event
import time
import logging

# Cấu hình logging
logging.basicConfig(
    filename='simple_service.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
)

class SimpleService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SimplePythonService"  # Tên của service
    _svc_display_name_ = "Simple Python Service"  # Tên hiển thị trong Services
    _svc_description_ = "A simple Python service that logs messages periodically."

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
        while self.running:
            logging.info("Service is running...")
            time.sleep(5)  # Lặp lại mỗi 5 giây
        logging.info("Service has stopped.")

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(SimpleService)
