from ui import WiresharkApp
import tkinter as tk

def main():
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
