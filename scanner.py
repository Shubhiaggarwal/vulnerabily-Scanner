import requests
from bs4 import BeautifulSoup
import socket 
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time

import matplotlib
matplotlib.use('Agg')  # Disable Tkinter backend


import os
# CLEAN URL
def clean_url(url):
    url = url.strip().replace("'", "").replace('"', "")
    if url.endswith("/"):
        url = url[:-1]
    return url

# -----------------------------
#   CHECK FOR SQL INJECTION
# -----------------------------
def check_sql_injection(url):
    payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1"]
    vulns = []

    for p in payloads:
        try:
            res = requests.get(url, params={"id": p}, timeout=5)
            if any(x in res.text.lower() for x in ["sql", "syntax", "warning"]):
                vulns.append(f"{url}?id={p}")
        except:
            pass

    return vulns

# -----------------------------
#   CHECK FOR XSS
# -----------------------------
def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    try:
        res = requests.get(url, params={"q": payload}, timeout=5)
        if payload in res.text:
            return True
    except:
        pass
    return False

# -----------------------------
#   ADMIN PANEL FINDER
# -----------------------------
def admin_panel_scan(url):
    panels = ["admin", "admin/login", "cpanel", "administrator"]
    found = []

    for p in panels:
        check = f"{url}/{p}"
        try:
            res = requests.get(check, timeout=5)
            if res.status_code == 200:
                found.append(check)
        except:
            pass

    return found

# -----------------------------
#      PORT SCANNER
# -----------------------------
def port_scanner(domain):
    open_ports = []
    common_ports = [80, 443, 8080, 21, 22, 3306]

    for port in common_ports:
        s = socket.socket()
        s.settimeout(0.4)

        try:
            s.connect((domain, port))
            open_ports.append(port)
        except:
            pass

    return open_ports
#----------add directory brute forcing-----
def directory_scan(url):
    directories = ["uploads", "backup", "images", "tmp", "logs", "robots.txt"]
    found = []

    for d in directories:
        check = f"{url}/{d}"
        try:
            res = requests.get(check, timeout=5)
            if res.status_code == 200:
                found.append(check)
        except:
            pass

    return found

#------- ADD sensitive file dertection---
def sensitive_file_scan(url):
    sensitive_files = ["config.php", "database.sql", "backup.zip", ".env", ".htaccess"]
    exposed = []

    for file in sensitive_files:
        check = f"{url}/{file}"
        try:
            res = requests.get(check, timeout=5)
            if res.status_code == 200:
                exposed.append(check)
        except:
            pass

    return exposed

#-----function tom risk level----
def risk_rating(vulns):
    if vulns:
        return "High"
    return "Low"
#--------screen shorts of website------

        # --------------------------------------

def take_screenshot(url, filename):
    try:
        # Create folder automatically
        folder = "static/screenshots"
        os.makedirs(folder, exist_ok=True)

        # Chrome options for server/headless mode
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")

        # Start Chrome
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.get(url)
        time.sleep(3)

        # Save screenshot
        path = os.path.join(folder, f"{filename}.png")
        driver.save_screenshot(path)
        driver.quit()

        print("📸 Screenshot saved:", path)
        return path

    except Exception as e:
        print("❌ Screenshot Error:", e)
        try:
            driver.quit()
        except:
            pass
        return None



#-------------pie chart---------
import matplotlib.pyplot as plt

def generate_risk_pie_chart(sql, xss, panels, dirs, sensitive):
    # Assign CVSS-like weights
    scores = [
        9.8 if sql else 0,
        6.1 if xss else 0,
        7.5 if panels else 0,
        6.0 if dirs else 0,
        9.0 if sensitive else 0
    ]

    labels = ["SQL Injection", "XSS", "Admin Panels", "Directories", "Sensitive Files"]

    # Remove items with zero score
    filtered_labels = []
    filtered_scores = []
    for l, s in zip(labels, scores):
        if s > 0:
            filtered_labels.append(l)
            filtered_scores.append(s)

    if not filtered_scores:
        print("⚠ No vulnerabilities found — pie chart skipped.")
        return

    plt.figure(figsize=(7,7))
    plt.pie(filtered_scores, labels=filtered_labels, autopct='%1.1f%%')
    plt.title("Risk Distribution (CVSS 3.1)")
    plt.savefig("reports/risk_piechart.png")
    plt.close()

    print("📊 Pie chart saved: reports/risk_piechart.png")
 
# -----------------------------
#      START SCANNING
# -----------------------------
def start_scan(url):
    url = clean_url(url)
    print("\n🔍 Starting Vulnerability Scan...\n")

    screenshot_paths = {}

    domain = url.replace("http://", "").replace("https://", "").split("/")[0]

    # SQL Injection
    sql_vulns = check_sql_injection(url)
    print("✔ SQL Injection Scan Completed")
    if sql_vulns:
      screenshot_paths["sql"] = take_screenshot(sql_vulns[0], "sql_injection_proof")
    else:
      screenshot_paths["sql"] = None



    # XSS
    xss = check_xss(url)
    print("✔ XSS Scan Completed")
    if xss:
     screenshot_paths["xss"] = take_screenshot(url + "?q=<script>alert('XSS')</script>", "xss_proof")
    else:
     screenshot_paths["xss"] = None


    # Admin Panel Finder
    panels = admin_panel_scan(url)
    print("✔ Admin Panel Scan Completed")
    if panels:
     screenshot_paths["admin"] = take_screenshot(panels[0], "admin_panel")
    else:
     screenshot_paths["admin"] = None

    # Directory Brute Forcing
    dirs = directory_scan(url)
    print("✔ Directory Scan Completed")
    if dirs:
      screenshot_paths["directory"] = take_screenshot(dirs[0], "directory_proof")
    else:
      screenshot_paths["directory"] = None

    # Sensitive File Detection
    sensitive = sensitive_file_scan(url)
    print("✔ Sensitive File Scan Completed")
    if sensitive:
      screenshot_paths["sensitive"] = take_screenshot(
        sensitive[0],
        f"sensitive_{sensitive[0].split('/')[-1]}"
    )
    else:
      screenshot_paths["sensitive"] = None


    # Port Scanning
    ports = port_scanner(domain)
    print("✔ Port Scan Completed\n")
    # Port Scanning
    ports = port_scanner(domain)
    print("✔ Port Scan Completed\n")
    # Generate Risk Pie Chart
    generate_risk_pie_chart(
    sql=bool(sql_vulns),
    xss=xss,
    panels=bool(panels),
    dirs=bool(dirs),
    sensitive=bool(sensitive)
)


    # SAVE REPORT
    with open("reports/report.txt", "w") as f:
        f.write("=== Vulnerability Report ===\n\n")
        f.write(f"URL: {url}\n\n")

        f.write("SQL Injection:\n")
        f.write(str(sql_vulns) + "\n" if sql_vulns else "No SQLi detected\n")

        f.write("\nXSS:\n")
        f.write("Vulnerable\n" if xss else "No XSS found\n")

        f.write("\nAdmin Panels:\n")
        f.write(str(panels) + "\n" if panels else "None found\n")

        f.write("\nOpen Ports:\n")
        f.write(str(ports) + "\n")

        f.write("\nDirectories Found:\n")
        f.write(str(dirs) + "\n" if dirs else "No exposed directories found\n")
        
        f.write("\nSensitive Files:\n")
        f.write(str(sensitive) + "\n" if sensitive else "No sensitive files exposed\n")
        
        f.write("\nRisk Ratings:\n")
        f.write(f"SQL Injection: {risk_rating(sql_vulns)}\n")
        f.write(f"XSS: {'High' if xss else 'Low'}\n")
        f.write(f"Open Ports: {'Medium' if ports else 'Low'}\n")
        f.write(f"Admin Panel Exposure: {'High' if panels else 'Low'}\n")
        f.write(f"Directory Exposure: {'Medium' if dirs else 'Low'}\n")
        f.write(f"Sensitive Files: {'Critical' if sensitive else 'Low'}\n")

    risk_ratings = {
    "sql": risk_rating(sql_vulns),
    "xss": "High" if xss else "Low",
    "ports": "Medium" if ports else "Low",
    "admin": "High" if panels else "Low",
    "directories": "Medium" if dirs else "Low",
    "sensitive": "Critical" if sensitive else "Low"
}
    result = {
    "cleaned_url": url,
    "sql_injection": sql_vulns,
    "xss": xss,
    "admin_panels": panels,
    "directories": dirs,
    "sensitive_files": sensitive,
    "ports": ports,
    "risk": risk_ratings,
    "screenshots": screenshot_paths

}
    return result



print("📄 Report saved to reports/report.txt")
print("\n🎉 Scan Completed!")

# RUN
#url = clean_url(input("Enter website URL (with http/https): "))
# start_scan(url)
# -----------------------------------
# DO NOT RUN ANYTHING AUTOMATICALLY
# -----------------------------------

# The main function Flask will call:
def run_scanner(url):
    return start_scan(url)



