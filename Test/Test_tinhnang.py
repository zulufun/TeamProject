import tkinter as tk
from tkinter import ttk
from threading import Thread
import speedtest
import time


class NetworkSpeedApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Speed Test")
        self.root.geometry("500x400")
        self.root.configure(bg="#282c34")
        self.root.resizable(False, False)

        # Tiêu đề
        self.title_label = tk.Label(
            root, text="Kiểm Tra Tốc Độ Mạng", font=("Arial", 18, "bold"),
            bg="#282c34", fg="#61dafb"
        )
        self.title_label.pack(pady=20)

        # Vùng hiển thị kết quả
        self.result_frame = tk.Frame(root, bg="#282c34")
        self.result_frame.pack(pady=20)

        self.download_label = tk.Label(
            self.result_frame, text="Download:", font=("Arial", 14),
            bg="#282c34", fg="white"
        )
        self.download_label.grid(row=0, column=0, padx=20, pady=10, sticky="w")
        self.download_value = tk.Label(
            self.result_frame, text="--- Mbps", font=("Arial", 14, "bold"),
            bg="#282c34", fg="#61dafb"
        )
        self.download_value.grid(row=0, column=1, padx=20, pady=10, sticky="w")

        self.upload_label = tk.Label(
            self.result_frame, text="Upload:", font=("Arial", 14),
            bg="#282c34", fg="white"
        )
        self.upload_label.grid(row=1, column=0, padx=20, pady=10, sticky="w")
        self.upload_value = tk.Label(
            self.result_frame, text="--- Mbps", font=("Arial", 14, "bold"),
            bg="#282c34", fg="#61dafb"
        )
        self.upload_value.grid(row=1, column=1, padx=20, pady=10, sticky="w")

        # Nút bắt đầu
        self.start_button = tk.Button(
            root, text="Bắt đầu đo", font=("Arial", 14), bg="#61dafb",
            fg="white", activebackground="#2188ff", activeforeground="white",
            command=self.start_test
        )
        self.start_button.pack(pady=20)

        # Hiệu ứng Progress Bar
        self.progress = ttk.Progressbar(root, mode="indeterminate", length=300)
        self.progress.pack(pady=10)

        # Nhãn trạng thái
        self.status_label = tk.Label(
            root, text="", font=("Arial", 12), bg="#282c34", fg="white"
        )
        self.status_label.pack()

    def start_test(self):
        self.start_button.config(state=tk.DISABLED)
        self.status_label.config(text="Đang đo tốc độ mạng...")
        self.progress.start(10)

        # Chạy kiểm tra trong luồng riêng
        Thread(target=self.run_speed_test).start()

    def run_speed_test(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()

            # Hiệu ứng tải xuống
            for _ in range(5):
                self.status_label.config(text="Đang đo tốc độ Download...")
                time.sleep(0.5)

            download_speed = st.download() / 1_000_000  # Mbps

            # Hiệu ứng tải lên
            for _ in range(5):
                self.status_label.config(text="Đang đo tốc độ Upload...")
                time.sleep(0.5)

            upload_speed = st.upload() / 1_000_000  # Mbps

            # Cập nhật giao diện
            self.download_value.config(text=f"{download_speed:.2f} Mbps")
            self.upload_value.config(text=f"{upload_speed:.2f} Mbps")
            self.status_label.config(text="Đo tốc độ hoàn tất!")
        except Exception as e:
            self.status_label.config(text="Lỗi: Không thể đo tốc độ mạng.")
        finally:
            self.start_button.config(state=tk.NORMAL)
            self.progress.stop()


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSpeedApp(root)
    root.mainloop()
