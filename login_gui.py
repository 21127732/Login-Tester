# login_gui.py

import tkinter as tk
from tkinter import ttk
from login import init_driver, login_to_site, quit_driver
import pandas as pd
import os

def center_window(window, width=580, height=400):
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = int((screen_width - width) / 2)
    y = int((screen_height - height) / 2)
    window.geometry(f"{width}x{height}+{x}+{y}")

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Auto Login GUI")
        center_window(self.root)

        self.username_var = tk.StringVar(value="tomsmith")
        self.password_var = tk.StringVar(value="SuperSecretPassword!")
        self.headless_var = tk.BooleanVar(value=False)

        frame = ttk.Frame(self.root)
        frame.pack(padx=20, pady=20, fill=tk.X)

        ttk.Label(frame, text="👤 Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, width=40, textvariable=self.username_var).grid(row=0, column=1, pady=5)

        ttk.Label(frame, text="🔒 Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, width=40, textvariable=self.password_var, show="*").grid(row=1, column=1, pady=5)

        ttk.Checkbutton(frame, text="Chạy chế độ headless", variable=self.headless_var).grid(row=2, column=1, sticky=tk.W, pady=5)

        ttk.Button(frame, text="🚀 Đăng nhập 3 lần", command=self.run_login).grid(row=3, column=1, pady=15)

        self.log_text = tk.Text(self.root, height=10)
        self.log_text.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

    def run_login(self):
        self.log_text.delete(1.0, tk.END)
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        headless = self.headless_var.get()

        if not username or not password:
            self.log_text.insert(tk.END, "❌ Vui lòng nhập đầy đủ thông tin đăng nhập.\n")
            return

        try:
            driver = init_driver(headless)
        except Exception as e:
            self.log_text.insert(tk.END, f"❌ Không thể khởi tạo trình duyệt: {str(e)}\n")
            return

        # Tạo cấu trúc bảng
        columns = [
            "TC ID", "Test case name", "Test case description", "Pre-processed steps",
            "Processed steps", "Expected results", "Actual results", "Pass / Fail", "Note"
        ]
        result_data = []

        for i in range(1, 4):  # 3 lần chạy login
            status, message = login_to_site(driver, username, password)
            tc_id = f"TC{str(i).zfill(3)}"
            row = [tc_id] + ["" for _ in range(6)] + ["Pass" if status == "success" else "Fail"] + [""]
            result_data.append(row)

            if status == "success":
                self.log_text.insert(tk.END, f"[{tc_id}] ✅ Thành công: {message.strip()}\n")
            elif status == "fail":
                self.log_text.insert(tk.END, f"[{tc_id}] ⚠️ Thất bại: {message.strip()}\n")
            else:
                self.log_text.insert(tk.END, f"[{tc_id}] ❌ Lỗi: {message.strip()}\n")

        quit_driver(driver)

        df = pd.DataFrame(result_data, columns=columns)
        output_path = os.path.join(os.getcwd(), "TestCase.xlsx")
        df.to_excel(output_path, index=False)

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
