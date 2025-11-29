import os
import threading
import socket
import ssl
import whois
import dns.resolver
import webbrowser
import requests
import builtwith
import datetime
import tempfile
from fpdf import FPDF
from bs4 import BeautifulSoup
from tkinter import Tk, Label, Entry, Button, Text, Scrollbar, Canvas, messagebox, END, DISABLED, NORMAL
from PIL import Image, ImageTk
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# --- Constants ---
ADMIN_PATHS = [
    'admin', 'login', 'cpanel', 'adminstrator', 'wp-admin', 'user', 'backend', 'manage', 'control'
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
RESULTS_DIR = os.path.join(OUTPUT_DIR, "results")
SCREENSHOTS_DIR = os.path.join(OUTPUT_DIR, "screenshots")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)


# --- Utility Functions ---

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def get_geolocation(ip):
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = resp.json()
        city = data.get("city", "N/A")
        region = data.get("region", "N/A")
        country = data.get("country", "N/A")
        return f"{city}, {region}, {country}"
    except Exception:
        return "N/A"


def get_whois_info(domain):
    try:
        return whois.whois(domain)
    except Exception:
        return None


def get_dns_records(domain):
    records = {}
    for t in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, t, lifetime=5)
            records[t] = [r.to_text() for r in answers]
        except Exception:
            records[t] = []
    return records


def get_http_headers(url):
    try:
        r = requests.get(url, timeout=7, allow_redirects=True)
        return r.headers
    except Exception:
        return None


def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('OrganizationName') or issuer.get('commonName') or "N/A"
                not_before = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M%S %Y %Z")
                not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                return issuer_name, not_before, not_after
    except Exception:
        return None, None, None


def check_robots_sitemap(domain):
    results = {}
    for file in ['robots.txt', 'sitemap.xml']:
        try:
            url = f"http://{domain}/{file}"
            r = requests.get(url, timeout=5)
            results[file] = r.text if r.status_code == 200 else None
        except Exception:
            results[file] = None
    return results


def brute_force_admin_panels(domain):
    found = []
    for path in ADMIN_PATHS:
        try:
            r = requests.get(f"http://{domain}/{path}", timeout=5)
            if r.status_code == 200:
                found.append(f"http://{domain}/{path}")
        except Exception:
            continue
    return found


def scrape_html_meta(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=7)
        soup = BeautifulSoup(r.text, "lxml")
        metas = {}
        for tag in soup.find_all("meta"):
            if 'name' in tag.attrs and 'content' in tag.attrs:
                metas[tag.attrs['name'].lower()] = tag.attrs['content']
            elif 'property' in tag.attrs and 'content' in tag.attrs:
                metas[tag.attrs['property'].lower()] = tag.attrs['content']
        return metas
    except Exception:
        return {}


def detect_tech_stack(domain):
    try:
        return builtwith.parse(f"http://{domain}")
    except Exception:
        return {}


def take_screenshot(domain):
    try:
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--window-size=1200x800')
        driver = webdriver.Chrome(options=options)
        driver.get(f"http://{domain}")
        path = os.path.join(SCREENSHOTS_DIR, f"{domain}.png")
        driver.save_screenshot(path)
        driver.quit()
        return path
    except Exception:
        return None


def write_report(domain, content):
    path = os.path.join(RESULTS_DIR, f"{domain} report.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# --- GUI Class ---

class ReconApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AUTOMATED RECON TOOL")
        self.root.geometry("900x650")
        self.root.resizable(False, False)

        # Set icon
        try:
            icon_path = os.path.join(ASSETS_DIR, "app_icon.ico")
            self.root.iconbitmap(icon_path)
        except Exception as e:
            print(f"[!] Icon Load Failed: {e}")

        # Set background
        try:
            bg_path = os.path.join(ASSETS_DIR, "background.png")
            bg_img = Image.open(bg_path).resize((900, 650))
            self.bg_photo = ImageTk.PhotoImage(bg_img)
            self.canvas = Canvas(self.root, width=900, height=650)
            self.canvas.pack(fill="both", expand=True)
            self.canvas.create_image(0, 0, image=self.bg_photo, anchor="nw")
        except Exception as e:
            print(f"[!] Background Load Failed: {e}")
            self.canvas = Canvas(self.root, width=900, height=650, bg="#000")
            self.canvas.pack(fill="both", expand=True)

        # Add Header Text
        self.canvas.create_text(450, 30, text="AUTOMATED RECON TOOL", font=("Arial", 20, "bold"), fill="#EE1532")

        # Entry field for target domain
        self.canvas.create_text(450, 70, text="Target Domain:", font=("Arial", 14), fill="#00FF00")
        self.entry = Entry(self.root, font=("Arial", 13), bg="#111", fg="#0f0", insertbackground="#0f0", width=50)
        self.entry_window = self.canvas.create_window(450, 100, window=self.entry)

        # Buttons
        self.start_btn = Button(self.root, text="Start Recon", font=("Arial", 12), bg="#00cc00", fg="black",
                                command=self.start_recon_thread)
        self.start_btn_window = self.canvas.create_window(370, 140, window=self.start_btn)

        self.clear_btn = Button(self.root, text="Clear Output", font=("Arial", 12), bg="#cc0000", fg="black",
                                command=self.clear_output)
        self.clear_btn_window = self.canvas.create_window(530, 140, window=self.clear_btn)

        self.info_btn = Button(self.root, text="Project Info", font=("Arial", 12), bg="#007acc", fg="white",
                               command=self.open_project_info)
        self.info_btn_window = self.canvas.create_window(450, 180, window=self.info_btn)

        # Output Text area
        self.output_text = Text(self.root, font=("Consolas", 11), bg="#000", fg="#00FF00", insertbackground="#0f0")
        self.output_text.config(state=DISABLED)
        self.output_text_window = self.canvas.create_window(450, 430, width=600, height=300, window=self.output_text)

        self.scrollbar = Scrollbar(self.root, command=self.output_text.yview)
        self.output_text.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar_window = self.canvas.create_window(750, 430, height=300, window=self.output_text)

    def clear_output(self):
        self.output_text.config(state=NORMAL)
        self.output_text.delete("1.0", END)
        self.output_text.config(state=DISABLED)

    def log(self, msg):
        self.output_text.config(state=NORMAL)
        self.output_text.insert(END, msg + "\n")
        self.output_text.see(END)
        self.output_text.config(state=DISABLED)

    def open_project_info(self):
        html_content = """
    <!DOCTYPE html>
<html>
<head>
    <title>Project Information</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f2f2f2;
        }

         .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 50px 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.2);
            border-radius: 4px;
            position: relative;
         }
          .photo {
             position: absolute;
             top: 20px;
             right: 20px;
             width: 100px;
             height: 100px;
             background-image: url('data:image/png;base64, ')
             background-size: cover;
             border-radius: 50%;
             box-shadow: 0 0 10px rgba(0, 0, 0, 0,2);
          }

          h1 {
              font-size: 36px;
              margin-bottom: 30px;
          }

          p {
              font-size: 18px;
              line-height: 1.5;
              margin-bottom: 20px;
          }

          table {
              width: 100%;
              margin-bottom: 20px;
              border-collapse: collapse;
          }

          table td,
          table th {
              padding: 10px;
              text-align: left;
              border: 1px solid #ddd;
          }

          table th {
              background-color: #f2f2f2;
              font-size: 18px;
          }

          @media only screen and (max-width: 600px) {
               .container {
                  padding: 30px 10px;
               }
               h1 {
                   font-size: 24px;
               }
               p {
                   font-size: 16px;
               }
                .photo {
                   width: 100px;
                   height: 100px;
                   top: 10px;
                   right: 10px;
                }
                table td,
                table th {
                    padding: 5px;
                    font-size: 16px;
                }
                table th {
                    font-size: 16px;
                }
          }
    </style>
</head>
<body>
    <div class="container">
    <div class="photo"></div>
        <h1>Project Information</h1>
        <p>This project was developed by <strong>Anonymous</strong> as part of a Cyber Security Internship. This project is designed to Secure the Organizations in Real World from Cyber Frauds performed by Hackers.</p>
        <table>
            <thead>
                <tr>
                    <th>Project Details</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Project Name</td>
                    <td>Automatic Reconnaissance with python</td>
                </tr>
                <tr>
                    <td>Project Description</td>
                    <td>Automated Python-based reconnaissance tool for efficient and comprehensive security information gathering.</td>
                </tr>
                <tr>
                    <td>Project Start Date</td>
                    <td>          </td>
                </tr>
                <tr>
                    <td>Project End Date</td>
                    <td>            </td>
                </tr>
                <tr>
                    <td>Project Status</td>
                    <td><strong>Completed</strong></td>
                </tr>
            </tbody>
        </table>
        <h2>Developer Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Employee ID</th>
                    <th>Email</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>SAI VANDANI</td>
                    <td>ST#IS#7695</td>
                    <td>saivandani3@gmail.com</td>
                </tr>
        </table>

        <h2>Company Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Company</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Name</td>
                    <td>Supraja Technologies</td>
                </tr>
                <tr>
                    <td>Email</td>
                    <td>contact@suprajatechnologies.com</td>
                </tr>
            </tbody>    
        </table>
    """
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as f:
            f.write(html_content)
            temp_file_path = f.name
        webbrowser.open(f"file://{temp_file_path}")

    def start_recon_thread(self):
        domain = self.entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Error", "Please enter a valid domain or URL.")
            return
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
        self.clear_output()
        self.log(f"Starting reconnaissance on: {domain}\n")
        self.start_btn.config(state="disabled")
        threading.Thread(target=self.run_recon, args=(domain,), daemon=True).start()

    def run_recon(self, domain):
        try:
            ip = resolve_ip(domain)
            self.log("=== Basic Recon ===")
            self.log(f"[\u2713] IP Address: {ip or 'Not Found'}")
            self.log(f"[\u2713] Location: {get_geolocation(ip) if ip else 'N/A'}")

            self.log("\n=== Whois Info ===")
            w = get_whois_info(domain)
            if w:
                self.log(f"Domain: {w.domain_name}")
                self.log(f"Registrar: {w.registrar}")
                self.log(f"Created: {w.creation_date}")
                self.log(f"Expires: {w.expiration_date}")
            else:
                self.log("Whois data not found.")

            self.log("\n=== DNS Records ===")
            for t, vals in get_dns_records(domain).items():
                self.log(f"{t}: {', '.join(vals) if vals else 'None'}")

            self.log("\n=== HTTP Headers ===")
            headers = get_http_headers(f"http://{domain}")
            if headers:
                for k, v in headers.items():
                    self.log(f"{k}: {v}")
            else:
                self.log("Could not retrieve HTTP headers.")

            self.log("\n=== SSL Info ===")
            issuer, start, end = get_ssl_info(domain)
            if issuer:
                self.log(f"Issuer: {issuer}")
                self.log(f"Valid From: {start.strftime('%Y-%m-%d')}")
                self.log(f"Valid Until: {end.strftime('%Y-%m-%d')}")
            else:
                self.log("No SSL info found.")

            self.log("\n=== Admin Panel Finder ===")
            panels = brute_force_admin_panels(domain)
            if panels:
                for url in panels:
                    self.log(f"[+] {url}")
            else:
                self.log("No admin panels found.")

            self.log("\n=== HTML Meta Data ===")
            meta = scrape_html_meta(domain)
            for k, v in meta.items():
                self.log(f"{k}: {v}")

            self.log("\n=== Tech Stack ===")
            techs = detect_tech_stack(domain)
            for k, v in techs.items():
                self.log(f"{k}: {', '.join(v)}")

            self.log("\n=== Screenshot ===")
            screenshot = take_screenshot(domain)
            self.log(f"Screenshot saved: {screenshot}" if screenshot else "Screenshot failed or skipped.")

            self.log("\n=== Report Saved ===")
            report = write_report(domain, self.output_text.get("1.0", END))
            self.log(f"Report path: {report}")

            self.log("\n[\u2713] Reconnaissance complete.")

        except Exception as e:
            self.log(f"[!] Error: {e}")
        finally:
            self.start_btn.config(state="normal")


# --- Run ---

if __name__ == "__main__":
    root = Tk()
    app = ReconApp(root)
    root.mainloop()