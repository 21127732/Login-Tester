# login.py

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager
import tempfile
import os
import time

def init_driver(headless=False):
    chrome_options = Options()

    if headless:
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--blink-settings=imagesEnabled=false")

    # Tắt các dịch vụ liên quan đến quản lý mật khẩu
    prefs = {
        "credentials_enable_service": False,
        "profile.password_manager_enabled": False,
        "profile.password_manager_leak_detection": False  # Vô hiệu hóa cảnh báo rò rỉ mật khẩu
    }
    chrome_options.add_experimental_option("prefs", prefs)

    # Tùy chọn bổ sung để giảm thiểu các cảnh báo bảo mật
    chrome_options.add_argument("--password-store=basic")


    return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

def wait_for_page(driver, wait_time=10):
    WebDriverWait(driver, wait_time).until(
        lambda d: d.execute_script("return document.readyState") == "complete"
    )

def login_to_site(driver, username, password):
    try:
        driver.get("https://the-internet.herokuapp.com/login")
        wait_for_page(driver)

        driver.find_element(By.ID, "username").send_keys(username)
        driver.find_element(By.ID, "password").send_keys(password)
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        time.sleep(2)

        message = driver.find_element(By.ID, "flash").text
        if "You logged into a secure area!" in message:
            return "success", message
        else:
            return "fail", message
    except Exception as e:
        return "error", str(e)

def quit_driver(driver):
    driver.quit()
