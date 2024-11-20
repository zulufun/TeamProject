import win32serviceutil
import win32service
import win32event
import servicemanager
import logging
import time
import os

# Cấu hình log
logging.basicConfig(
    filename=os.path.join(os.getcwd(), "service.log"),
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

class DemoService(win32serviceutil.ServiceFramework):
    _svc_name_ = "DemoService"
    _svc_display_name_ = "Demo Python Service"
    _svc_description_ = "A demo Windows Service written in Python."

    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        logging.info("Service is stopping...")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.running = False

    def SvcDoRun(self):
        logging.info("Service is starting...")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        self.main()

    def main(self):
        while self.running:
            logging.info("Service is running...")
            time.sleep(60)  # Thực hiện công việc mỗi phút

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(DemoService)
