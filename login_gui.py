# login_gui.py

import tkinter as tk
from tkinter import ttk, messagebox
from login import init_driver, login_to_site, quit_driver
import pandas as pd
import os


def center_window(window, width=580, height=430):
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
        (text.swapcase(), "Đảo hoa-thường")
    ]

def generate_security_inputs():
    return [
        ("' OR 1=1 --", "[Security] SQLi - OR 1=1"),
        ("<script>alert(1)</script>", "[Security] XSS - script tag"),
        ("admin; ls -al", "[Security] Command Injection"),
        ("../../etc/passwd", "[Security] Path Traversal"),
        ("<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", "[Security] XXE Payload")
    ]

def compare_excel(expected_path: str, actual_path: str, report_path: str):
    try:
        df_expected = pd.read_excel(expected_path)
        df_actual = pd.read_excel(actual_path)
        diffs = []
        for _, row in df_expected.iterrows():
            tc_id = row['TC ID']
            actual_row = df_actual[df_actual['TC ID'] == tc_id]
            if actual_row.empty:
                diffs.append(f"{tc_id}: Không tồn tại trong file mới")
            else:
                actual_row = actual_row.iloc[0]
                for col in ['Expected results', 'Actual results', 'Pass / Fail']:
                    if str(row[col]).strip() != str(actual_row[col]).strip():
                        diffs.append(f"{tc_id}: Sai lệch ở cột '{col}'")
                        break
        with open(report_path, "w", encoding="utf-8") as f:
            if not diffs:
                f.write("✅ Regression PASS - Không có sai lệch\n")
            else:
                f.write("❌ Regression FAIL - Có sai lệch:\n")
                for diff in diffs:
                    f.write(f"- {diff}\n")
    except Exception as e:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"❌ Lỗi khi so sánh: {str(e)}\n")

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Auto Login GUI")
        center_window(self.root)

        self.username_var = tk.StringVar(value="tomsmith")
        self.password_var = tk.StringVar(value="SuperSecretPassword!")
        self.headless_var = tk.BooleanVar(value=False)
        self.regression_mode = tk.BooleanVar(value=False)

        frame = ttk.Frame(self.root)
        frame.pack(padx=20, pady=20, fill=tk.X)

        ttk.Label(frame, text="👤 Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, width=40, textvariable=self.username_var).grid(row=0, column=1, pady=5)

        ttk.Label(frame, text="🔒 Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, width=40, textvariable=self.password_var, show="*").grid(row=1, column=1, pady=5)

        ttk.Checkbutton(frame, text="Chạy chế độ headless", variable=self.headless_var).grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Checkbutton(frame, text="🧪 Regression Mode", variable=self.regression_mode).grid(row=3, column=1, sticky=tk.W, pady=5)

        ttk.Button(frame, text="🚀 Chạy kiểm thử", command=self.run_login).grid(row=4, column=1, pady=10)

        self.log_text = tk.Text(self.root, height=20)
        self.log_text.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

    def run_login(self):
        self.log_text.delete(1.0, tk.END)
        base_username = self.username_var.get().strip()
        base_password = self.password_var.get().strip()
        headless = self.headless_var.get()
        regression = self.regression_mode.get()

        if not base_username or not base_password:
            messagebox.showerror("Thiếu thông tin", "Vui lòng nhập đầy đủ Username và Password")
            return

        try:
            driver = init_driver(headless)
        except Exception as e:
            self.log_text.insert(tk.END, f"❌ Không thể khởi tạo trình duyệt: {str(e)}\n")
            return

        columns = ["TC ID", "Test case name", "Test case description", "Pre-processed steps",
                   "Processed steps", "Expected results", "Actual results", "Pass / Fail", "Note"]
        result_data = []
        tc_index = 1

        for username_variant, test_name in generate_variants(base_username):
            status, message = login_to_site(driver, username_variant, base_password)
            result_data.append([f"TC{tc_index:03d}", f"[Username] {test_name}", "", "", f"{username_variant} / {base_password}",
                                "Pass" if username_variant == base_username else "Fail",
                                message.strip(), "Pass" if status == "success" else "Fail", ""])
            tc_index += 1

        for password_variant, test_name in generate_variants(base_password)[1:]:
            status, message = login_to_site(driver, base_username, password_variant)
            result_data.append([f"TC{tc_index:03d}", f"[Password] {test_name}", "", "", f"{base_username} / {password_variant}",
                                "Pass" if password_variant == base_password else "Fail",
                                message.strip(), "Pass" if status == "success" else "Fail", ""])
            tc_index += 1

        blanks = [("", base_password, "[Blank] Bỏ trống Username"),
                  (base_username, "", "[Blank] Bỏ trống Password"),
                  ("", "", "[Blank] Bỏ trống cả hai")]
        for u, p, test_name in blanks:
            status, message = login_to_site(driver, u, p)
            result_data.append([f"TC{tc_index:03d}", test_name, "", "", f"{u} / {p}",
                                "Fail", message.strip(), "Pass" if status == "success" else "Fail", ""])
            tc_index += 1

        for sec_input, test_name in generate_security_inputs():
            status, message = login_to_site(driver, sec_input, base_password)
            result_data.append([f"TC{tc_index:03d}", test_name, "", "", f"{sec_input} / {base_password}",
                                "Fail", message.strip(), "Pass" if status == "success" else "Fail", ""])
            tc_index += 1

        quit_driver(driver)

        output_path = os.path.join(os.getcwd(), "TestCaseRegress.xlsx" if regression else "TestCase.xlsx")
        df = pd.DataFrame(result_data, columns=columns)
        df.to_excel(output_path, index=False)

        if regression:
            expected_path = os.path.join(os.getcwd(), "TestCase.xlsx")
            if os.path.exists(expected_path):
                report_path = os.path.join(os.getcwd(), "RegressionReport.txt")
                compare_excel(expected_path, output_path, report_path)
                self.log_text.insert(tk.END, f"📄 Đã lưu báo cáo so sánh: {report_path}\n")
            else:
                self.log_text.insert(tk.END, "⚠️ Không tìm thấy file TestCase.xlsx để so sánh.\n")
        else:
            self.log_text.insert(tk.END, f"✅ Đã tạo file kiểm thử: {output_path}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
