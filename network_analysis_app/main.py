import tkinter as tk
from ui import WiresharkApp

def main():
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()