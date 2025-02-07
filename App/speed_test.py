import tkinter as tk
from tkinter import ttk
import threading
import speedtest

class NetworkSpeedTestWindow:
    def __init__(self, root):
        # Tạo cửa sổ phụ (Toplevel) cho tính năng kiểm tra tốc độ mạng
        self.window = tk.Toplevel(root)
        self.window.title("Network Speed Test")
        self.window.geometry("500x300")

        # Nút để bắt đầu kiểm tra tốc độ
        self.start_button = tk.Button(self.window, text="Start Speed Test", command=self.start_speed_test)
        self.start_button.pack(pady=10)

        # Text widget hiển thị kết quả
        self.result_text = tk.Text(self.window, wrap=tk.WORD, state='disabled', width=60, height=10)
        self.result_text.pack(padx=10, pady=10)

    def start_speed_test(self):
        # Vô hiệu hóa nút để tránh người dùng click nhiều lần trong khi đang chạy kiểm tra
        self.start_button.config(state=tk.DISABLED)
        # Xóa nội dung cũ và hiển thị thông báo bắt đầu kiểm tra
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, "Starting speed test...\n")
        self.result_text.config(state='disabled')
        # Chạy kiểm tra tốc độ trên một thread riêng để không làm treo giao diện
        threading.Thread(target=self.run_speed_test, daemon=True).start()

    def run_speed_test(self):
        try:
            st = speedtest.Speedtest()
            self.update_text("Finding best server...\n")
            st.get_best_server()

            self.update_text("Testing download speed...\n")
            download_speed = st.download() / 1_000_000  # Chuyển đổi từ bit/s sang Mbps

            self.update_text("Testing upload speed...\n")
            upload_speed = st.upload() / 1_000_000  # Chuyển đổi từ bit/s sang Mbps

            ping = st.results.ping

            result_str = (
                "\n===== Speed Test Results =====\n"
                f"Ping: {ping:.2f} ms\n"
                f"Download Speed: {download_speed:.2f} Mbps\n"
                f"Upload Speed: {upload_speed:.2f} Mbps\n"
            )
            self.update_text(result_str)
        except Exception as e:
            self.update_text(f"Error during speed test: {e}\n")
        finally:
            # Cho phép nút được kích hoạt lại sau khi kiểm tra xong
            self.start_button.config(state=tk.NORMAL)

    def update_text(self, text):
        # Cập nhật nội dung cho Text widget một cách thread-safe
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.config(state='disabled')

def open_network_speed_test_window(root):
    NetworkSpeedTestWindow(root)

# Chương trình chính
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Main Program")
    root.geometry("300x150")

    # Nút mở cửa sổ tính năng "Network Speed Test"
    open_button = tk.Button(root, text="Open Network Speed Test", command=lambda: open_network_speed_test_window(root))
    open_button.pack(pady=40)

    root.mainloop()
