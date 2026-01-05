import os
import sqlite3
import shutil
import datetime
import hashlib
import platform
import glob
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from fpdf import FPDF
from Registry import Registry

# --- SECTION 1: CORE FORENSIC LOGIC (Modified for GUI) ---

def calculate_file_hash(filepath):
    hasher = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
        return hasher.hexdigest()
    except Exception as e:
        return f"Error: {e}"

def convert_chrome_time(webkit_timestamp):
    try:
        epoch_start = datetime.datetime(1601, 1, 1)
        delta = datetime.timedelta(microseconds=int(webkit_timestamp))
        return epoch_start + delta
    except:
        return "Invalid Timestamp"

def convert_firefox_time(unix_timestamp):
    try:
        if not unix_timestamp: return "No Date"
        return datetime.datetime.fromtimestamp(unix_timestamp / 1000000.0)
    except:
        return "Invalid Timestamp"

def sanitize_text(text):
    if text is None: return ""
    return str(text).encode('latin-1', 'replace').decode('latin-1')

# --- SECTION 2: PDF REPORTING ENGINE ---

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Digital Forensic Analysis Report', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 10, f'Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def add_evidence_metadata(self, system_info, user_info):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Case Information:', 0, 1)
        self.set_font('Arial', '', 10)
        self.cell(0, 6, f'System OS: {system_info}', 0, 1)
        self.cell(0, 6, f'User Account: {user_info}', 0, 1)
        self.ln(5)

    def add_table_header(self):
        self.set_font('Arial', 'B', 9)
        self.set_fill_color(200, 220, 255)
        self.cell(40, 7, 'Timestamp', 1, 0, 'C', True)
        self.cell(20, 7, 'Source', 1, 0, 'C', True)
        self.cell(60, 7, 'Activity / Device', 1, 0, 'C', True)
        self.cell(70, 7, 'Details / URL', 1, 1, 'C', True)

    def add_table_row(self, time, source, title, url):
        self.set_font('Arial', '', 8)
        title = sanitize_text(title)
        url = sanitize_text(url)
        time = sanitize_text(time)
        if title == "": title = "[No Data]"
        if url == "": url = "[No Data]"
        title = (title[:35] + '...') if len(title) > 35 else title
        url = (url[:45] + '...') if len(url) > 45 else url
        self.cell(40, 6, time[:19], 1)
        self.cell(20, 6, source, 1)
        self.cell(60, 6, title, 1)
        self.cell(70, 6, url, 1, 1)

# --- SECTION 3: ANALYSIS FUNCTIONS (With Logger Callback) ---

def analyze_chrome(log_callback):
    log_callback("[*] Detecting Chrome Artifacts...")
    history_path = None
    system_name = platform.system()
    
    if system_name == "Windows":
        user_profile = os.environ.get('USERPROFILE')
        if user_profile:
            history_path = os.path.join(user_profile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'History')
    elif system_name == "Linux":
        paths = [os.path.expanduser("~/.config/google-chrome/Default/History"), os.path.expanduser("~/.config/chromium/Default/History")]
        for p in paths:
            if os.path.exists(p):
                history_path = p
                break

    if not history_path or not os.path.exists(history_path):
        log_callback("[-] Chrome History not found.")
        return []

    log_callback(f"[+] Found Chrome DB: {history_path}")
    temp_db = "temp_chrome.sqlite"
    extracted_data = []
    try:
        shutil.copy2(history_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 20;")
        for row in cursor.fetchall():
            extracted_data.append({
                'source': 'Chrome',
                'time': str(convert_chrome_time(row[3])),
                'title': row[1],
                'url': row[0]
            })
        conn.close()
        os.remove(temp_db)
        return extracted_data
    except Exception as e:
        log_callback(f"[-] Chrome Error: {e}")
        return []

def analyze_firefox(log_callback):
    log_callback("[*] Detecting Firefox Artifacts...")
    profile_pattern = ""
    system_name = platform.system()
    if system_name == "Windows":
        user_profile = os.environ.get('USERPROFILE')
        if user_profile:
            profile_pattern = os.path.join(user_profile, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles', '*.default*')
    elif system_name == "Linux":
        profile_pattern = os.path.expanduser("~/.mozilla/firefox/*.default*")

    profiles = glob.glob(profile_pattern)
    if not profiles:
        log_callback("[-] No Firefox profiles found.")
        return []

    db_path = os.path.join(profiles[0], "places.sqlite")
    if not os.path.exists(db_path): return []

    log_callback(f"[+] Found Firefox DB: {db_path}")
    temp_db = "temp_firefox.sqlite"
    extracted_data = []
    try:
        shutil.copy2(db_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 20;")
        for row in cursor.fetchall():
            extracted_data.append({
                'source': 'Firefox',
                'time': str(convert_firefox_time(row[3])),
                'title': row[1],
                'url': row[0]
            })
        conn.close()
        os.remove(temp_db)
        return extracted_data
    except Exception as e:
        log_callback(f"[-] Firefox Error: {e}")
        return []

def analyze_system_hive(log_callback):
    log_callback("[*] Detecting USB Registry Artifacts...")
    hive_path = "SYSTEM"
    
    if not os.path.exists(hive_path):
        log_callback("[-] 'SYSTEM' file not found in current folder.")
        return []
        
    extracted_data = []
    try:
        reg = Registry.Registry(hive_path)
        key = reg.open("ControlSet001\\Enum\\USBSTOR")
        
        for device in key.subkeys():
            clean_name = device.name().replace("Disk&Ven_", "").replace("&Prod_", " ").replace("&Rev_", "")
            for instance in device.subkeys():
                extracted_data.append({
                    'time': instance.timestamp().strftime("%Y-%m-%d %H:%M:%S"),
                    'source': 'USB Device',
                    'title': clean_name,    
                    'url': instance.name()
                })
        log_callback(f"[+] Found {len(extracted_data)} USB entries.")
        return extracted_data
    except Exception as e:
        log_callback(f"[-] Registry Analysis Failed: {e}")
        return []

# --- SECTION 4: GUI APPLICATION CLASS ---

class ForensicsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PyForensics - Digital Investigation Tool")
        self.root.geometry("600x500")
        
        # Styles
        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 10, "bold"))
        style.configure("TLabel", font=("Helvetica", 11))

        # Title Label
        title = tk.Label(root, text="PyForensics Dashboard", font=("Helvetica", 16, "bold"), fg="darkblue")
        title.pack(pady=10)

        # Checkboxes Frame
        frame_controls = tk.LabelFrame(root, text="Select Targets", padx=10, pady=10)
        frame_controls.pack(padx=20, pady=5, fill="x")

        self.var_chrome = tk.BooleanVar(value=True)
        self.var_firefox = tk.BooleanVar(value=True)
        self.var_usb = tk.BooleanVar(value=False)

        c1 = tk.Checkbutton(frame_controls, text="Google Chrome History", variable=self.var_chrome, font=("Arial", 10))
        c2 = tk.Checkbutton(frame_controls, text="Mozilla Firefox History", variable=self.var_firefox, font=("Arial", 10))
        c3 = tk.Checkbutton(frame_controls, text="USB Device History (Requires SYSTEM file)", variable=self.var_usb, font=("Arial", 10))
        
        c1.pack(anchor="w")
        c2.pack(anchor="w")
        c3.pack(anchor="w")

        # Run Button
        self.btn_run = ttk.Button(root, text="RUN ANALYSIS REPORT", command=self.start_thread)
        self.btn_run.pack(pady=15, ipadx=10, ipady=5)

        # Log Window
        tk.Label(root, text="Investigation Logs:", anchor="w").pack(fill="x", padx=20)
        self.log_area = scrolledtext.ScrolledText(root, height=12, font=("Consolas", 9))
        self.log_area.pack(padx=20, pady=5, fill="both", expand=True)

    def log(self, message):
        """Updates the text area in a thread-safe way"""
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def start_thread(self):
        """Runs analysis in a separate thread to keep GUI responsive"""
        self.btn_run.config(state="disabled")
        self.log_area.delete('1.0', tk.END) # Clear logs
        threading.Thread(target=self.run_analysis).start()

    def run_analysis(self):
        self.log(f"--- Starting Analysis at {datetime.datetime.now().strftime('%H:%M:%S')} ---")
        self.log(f"Platform: {platform.system()} | User: {os.getlogin()}")
        
        evidence = []
        
        # Chrome
        if self.var_chrome.get():
            evidence += analyze_chrome(self.log)
            
        # Firefox
        if self.var_firefox.get():
            evidence += analyze_firefox(self.log)
            
        # USB
        if self.var_usb.get():
            evidence += analyze_system_hive(self.log)

        # Report Generation
        if evidence:
            self.log("[*] Sorting evidence by timestamp...")
            evidence.sort(key=lambda x: x['time'], reverse=True)
            
            filename = f"Forensic_Report_{datetime.date.today()}.pdf"
            self.log(f"[*] Generating PDF: {filename}")
            
            try:
                pdf = PDFReport()
                pdf.add_page()
                pdf.add_evidence_metadata(platform.system(), os.getlogin())
                pdf.add_table_header()
                for entry in evidence:
                    pdf.add_table_row(entry['time'], entry['source'], entry['title'], entry['url'])
                pdf.output(filename)
                
                self.log(f"[SUCCESS] Report Saved: {os.path.abspath(filename)}")
                messagebox.showinfo("Success", f"Analysis Complete!\nReport saved as {filename}")
                
            except Exception as e:
                self.log(f"[!] PDF Error: {e}")
                messagebox.showerror("Error", f"Failed to create PDF: {e}")
        else:
            self.log("[!] No evidence found matching selected targets.")
            messagebox.showwarning("No Data", "No evidence found to report.")

        self.btn_run.config(state="normal")

# --- MAIN ENTRY POINT ---

if __name__ == "__main__":
    # Check dependencies before starting GUI
    try:
        import fpdf
        import Registry
    except ImportError as e:
        print(f"CRITICAL ERROR: Missing libraries. {e}")
        print("Run: pip install fpdf python-registry")
        exit()

    root = tk.Tk()
    app = ForensicsApp(root)
    root.mainloop()
