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

def generate_variants(text: str):
    return [
        (text, "Gốc"),
        (text.lower(), "Tất cả viết thường"),
        (text.upper(), "Tất cả viết hoa"),
        (text + " ", "Khoảng trắng ở cuối"),
        (" " + text, "Khoảng trắng ở đầu"),
        (text.capitalize(), "Viết hoa chữ cái đầu"),
        (text.swapcase(), "Đảo hoa-thường"),
        (text.strip() + "\n", "Ký tự xuống dòng ở cuối"),
        (text + "\t", "Ký tự tab ở cuối")
    ]

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

        ttk.Button(frame, text="🚀 Thử nhiều biến thể Username và Password", command=self.run_login).grid(row=3, column=1, pady=15)

        self.log_text = tk.Text(self.root, height=10)
        self.log_text.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

    def run_login(self):
        self.log_text.delete(1.0, tk.END)
        base_username = self.username_var.get().strip()
        base_password = self.password_var.get().strip()
        headless = self.headless_var.get()

        if not base_username or not base_password:
            self.log_text.insert(tk.END, "❌ Vui lòng nhập đầy đủ thông tin đăng nhập.\n")
            return

        try:
            driver = init_driver(headless)
        except Exception as e:
            self.log_text.insert(tk.END, f"❌ Không thể khởi tạo trình duyệt: {str(e)}\n")
            return

        columns = [
            "TC ID", "Test case name", "Test case description", "Pre-processed steps",
            "Processed steps", "Expected results", "Actual results", "Pass / Fail", "Note"
        ]
        result_data = []

        # --- Biến thể Username ---
        username_variants = generate_variants(base_username)
        for i, (username_variant, test_name) in enumerate(username_variants, start=1):
            status, message = login_to_site(driver, username_variant, base_password)
            tc_id = f"TC{str(i).zfill(3)}"
            processed = f"{username_variant} / {base_password}"
            expected = "Pass" if username_variant == base_username else "Fail"
            row = [tc_id, test_name, test_name, "", processed, expected, status.capitalize() if status in ["pass", "fail"] else message.strip(), "Pass" if status == "success" else "Fail", ""]
            result_data.append(row)

            if status == "success":
                self.log_text.insert(tk.END, f"[{tc_id}] ✅ Thành công với Username: '{username_variant}'\n")
            elif status == "fail":
                self.log_text.insert(tk.END, f"[{tc_id}] ⚠️ Thất bại với Username: '{username_variant}'\n")
            else:
                self.log_text.insert(tk.END, f"[{tc_id}] ❌ Lỗi với Username: '{username_variant}'\n")

        # --- Biến thể Password ---
        password_variants = generate_variants(base_password)
        for j, (password_variant, test_name) in enumerate(password_variants[1:], start=1):  # bỏ gốc
            status, message = login_to_site(driver, base_username, password_variant)
            tc_id = f"TC{str(len(username_variants) + j).zfill(3)}"
            processed = f"{base_username} / {password_variant}"
            expected = "Pass" if password_variant == base_password else "Fail"
            row = [tc_id, test_name, test_name, "", processed, expected, status.capitalize() if status in ["pass", "fail"] else message.strip(), "Pass" if status == "success" else "Fail", ""]
            result_data.append(row)

            if status == "success":
                self.log_text.insert(tk.END, f"[{tc_id}] ✅ Thành công với Password: '{password_variant}'\n")
            elif status == "fail":
                self.log_text.insert(tk.END, f"[{tc_id}] ⚠️ Thất bại với Password: '{password_variant}'\n")
            else:
                self.log_text.insert(tk.END, f"[{tc_id}] ❌ Lỗi với Password: '{password_variant}'\n")

        quit_driver(driver)

        df = pd.DataFrame(result_data, columns=columns)
        output_path = os.path.join(os.getcwd(), "TestCase.xlsx")
        df.to_excel(output_path, index=False)

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
