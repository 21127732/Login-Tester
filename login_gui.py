# login_gui.py (toàn bộ file đã cập nhật logic Expected results cho tất cả test case)

import tkinter as tk
from tkinter import ttk, messagebox
from login import init_driver, login_to_site, quit_driver
import pandas as pd
import os
import threading

stop_flag = False

def center_window(window, width=580, height=460):
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

        expected_ids = set(df_expected['TC ID'].dropna().tolist())
        actual_ids = set(df_actual['TC ID'].dropna().tolist())

        missing_in_actual = expected_ids - actual_ids
        extra_in_actual = actual_ids - expected_ids

        for tc_id in sorted(missing_in_actual):
            diffs.append(f"{tc_id}: Không tồn tại trong file kết quả")

        for tc_id in sorted(extra_in_actual):
            diffs.append(f"{tc_id}: Không tồn tại trong file kỳ vọng")

        for tc_id in sorted(expected_ids & actual_ids):
            row_exp = df_expected[df_expected['TC ID'] == tc_id].iloc[0]
            row_act = df_actual[df_actual['TC ID'] == tc_id].iloc[0]
            for col in ['Expected results', 'Actual results', 'Pass / Fail']:
                val_exp = str(row_exp[col]).strip()
                val_act = str(row_act[col]).strip()
                if val_exp != val_act:
                    diffs.append(f"{tc_id}: Sai lệch ở cột '{col}' (Kỳ vọng: '{val_exp}' ≠ Thực tế: '{val_act}')")
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

        ttk.Button(frame, text="🚀 Chạy kiểm thử", command=self.run_in_thread).grid(row=4, column=1, pady=10)
        self.stop_button = ttk.Button(frame, text="🛑 Dừng kiểm thử", command=self.stop_testing)
        self.stop_button.grid(row=5, column=1, pady=5)
        self.stop_button.state(['disabled'])

        self.log_text = tk.Text(self.root, height=20)
        self.log_text.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

    def run_in_thread(self):
        self.stop_button.state(['!disabled'])
        threading.Thread(target=self.run_login, daemon=True).start()

    def stop_testing(self):
        global stop_flag
        stop_flag = True
        self.log_text.insert(tk.END, "⚠️ Đã yêu cầu dừng kiểm thử. Sẽ dừng sau test case hiện tại...\n")
        self.stop_button.state(['disabled'])

    def run_login(self):
        global stop_flag
        stop_flag = False

        self.log_text.delete(1.0, tk.END)
        base_username = self.username_var.get().strip()
        base_password = self.password_var.get().strip()
        headless = self.headless_var.get()
        regression = self.regression_mode.get()

        if not base_username or not base_password:
            messagebox.showerror("Thiếu thông tin", "Vui lòng nhập đầy đủ Username và Password")
            self.stop_button.state(['disabled'])
            return

        try:
            driver = init_driver(headless)
        except Exception as e:
            self.log_text.insert(tk.END, f"❌ Không thể khởi tạo trình duyệt: {str(e)}\n")
            self.stop_button.state(['disabled'])
            return

        columns = ["TC ID", "Test case name", "Test case description", "Pre-processed steps",
                   "Processed steps", "Expected results", "Actual results", "Pass / Fail", "Note"]
        result_data = []
        tc_index = 1

        for username_variant, test_name in generate_variants(base_username):
            if stop_flag: break
            tc_id = f"TC{tc_index:03d}"
            status, message = login_to_site(driver, username_variant, base_password)
            expected_result = "Login Successfully" if username_variant == base_username else "Login Fail"
            actual_result = "Login Successfully" if status == "success" else "Login Fail"
            pass_fail = "Pass" if expected_result == actual_result else "Fail"
            result_data.append([tc_id, f"[Username] {test_name}", "", "", f"{username_variant} / {base_password}",
                                expected_result, actual_result, pass_fail, ""])
            self.log_text.insert(tk.END, f"✅ Đã chạy {tc_index}: {test_name}\n")
            tc_index += 1

        for password_variant, test_name in generate_variants(base_password)[1:]:
            if stop_flag: break
            tc_id = f"TC{tc_index:03d}"
            status, message = login_to_site(driver, base_username, password_variant)
            expected_result = "Login Successfully" if password_variant == base_password else "Login Fail"
            actual_result = "Login Successfully" if status == "success" else "Login Fail"
            pass_fail = "Pass" if expected_result == actual_result else "Fail"
            result_data.append([tc_id, f"[Password] {test_name}", "", "", f"{base_username} / {password_variant}",
                                expected_result, actual_result, pass_fail, ""])
            self.log_text.insert(tk.END, f"✅ Đã chạy {tc_index}: {test_name}\n")
            tc_index += 1

        blanks = [("", base_password, "[Blank] Bỏ trống Username"),
                  (base_username, "", "[Blank] Bỏ trống Password"),
                  ("", "", "[Blank] Bỏ trống cả hai")]
        for u, p, test_name in blanks:
            if stop_flag: break
            tc_id = f"TC{tc_index:03d}"
            status, message = login_to_site(driver, u, p)
            expected_result = "Login Successfully" if (u == base_username and p == base_password) else "Login Fail"
            actual_result = "Login Successfully" if status == "success" else "Login Fail"
            pass_fail = "Pass" if expected_result == actual_result else "Fail"
            result_data.append([tc_id, test_name, "", "", f"{u} / {p}",
                                expected_result, actual_result, pass_fail, ""])
            self.log_text.insert(tk.END, f"✅ Đã chạy {tc_index}: {test_name}\n")
            tc_index += 1

        for sec_input, test_name in generate_security_inputs():
            if stop_flag: break
            tc_id = f"TC{tc_index:03d}"
            status, message = login_to_site(driver, sec_input, base_password)
            expected_result = "Login Fail"
            actual_result = "Login Successfully" if status == "success" else "Login Fail"
            pass_fail = "Pass" if expected_result == actual_result else "Fail"
            result_data.append([tc_id, test_name, "", "", f"{sec_input} / {base_password}",
                                expected_result, actual_result, pass_fail, ""])
            self.log_text.insert(tk.END, f"✅ Đã chạy {tc_index}: {test_name}\n")
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

        if stop_flag:
            self.log_text.insert(tk.END, "🛑 Đã dừng kiểm thử sớm. Kết quả đã lưu những test đã chạy.\n")

        self.stop_button.state(['disabled'])

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
