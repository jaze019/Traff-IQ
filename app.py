# app.py (Version 4.2 - Corrected)

import sys
import logging
import time
import configparser
import requests
import ipaddress
import threading
import queue
import customtkinter as ctk
from collections import defaultdict
from scapy.all import sniff, TCP, IP

# --- 1. Read Configuration from config.ini ---
try:
    config = configparser.ConfigParser()
    config.read('config.ini')
    settings = config['Settings']

    interface_string = settings.get('interfaces', 'lo')
    INTERFACES = [iface.strip() for iface in interface_string.split(',')]

    PORT_SCAN_THRESHOLD = settings.getint('port_scan_threshold', 15)
    TIME_WINDOW = settings.getint('time_window', 30)
    ABUSEIPDB_KEY = settings.get('abuseipdb_api_key', 'YOUR_API_KEY_HERE')
except (configparser.Error, KeyError) as e:
    print(f"FATAL ERROR: Could not read config.ini: {e}")
    sys.exit(1)

# --- 2. Configure Logging to File ---
logging.basicConfig(
    filename='ids.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# --- 3. IP Intelligence Functions ---
def get_ip_geolocation(ip):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        response.raise_for_status()
        data = response.json()
        if data['status'] == 'success':
            return f"{data.get('city', 'N/A')}, {data.get('country', 'N/A')}"
        return "Location not found"
    except requests.RequestException:
        return "Geolocation lookup failed"


def get_ip_reputation(ip, api_key):
    if not api_key or api_key == 'YOUR_API_KEY_HERE':
        return "AbuseIPDB key not configured"
    try:
        response = requests.get('https://api.abuseipdb.com/api/v2/check',
                                params={'ipAddress': ip, 'maxAgeInDays': '90'},
                                headers={'Key': api_key, 'Accept': 'application/json'},
                                timeout=5)
        response.raise_for_status()
        data = response.json().get('data', {})
        score = data.get('abuseConfidenceScore', 0)
        return f"Abuse Score: {score}%"
    except requests.RequestException:
        return "Reputation lookup failed"


# --- 4. The Main Application Class ---
class IDS_GUI(ctk.CTk):
    def __init__(self, **kwargs):
        super().__init__()

        self.alert_queue = queue.Queue()
        self.stop_sniffing = threading.Event()
        self.sniffing_thread = None

        self.title("Mini IDS")
        self.geometry("800x500")
        ctk.set_appearance_mode("dark")

        self.title_label = ctk.CTkLabel(self, text="Mini Intrusion Detection System",
                                        font=ctk.CTkFont(size=20, weight="bold"))
        self.title_label.pack(pady=10)

        self.alert_textbox = ctk.CTkTextbox(self, state="disabled", font=("Courier", 13))
        self.alert_textbox.pack(pady=10, padx=10, fill="both", expand=True)

        # --- THE FIX: Removed the 'font' argument from the tag configuration ---
        self.alert_textbox.tag_config("danger", foreground="#ff4d4d")

        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.pack(pady=10, padx=10, fill="x")

        self.start_button = ctk.CTkButton(self.button_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side="left", padx=(0, 5), expand=True)

        self.stop_button = ctk.CTkButton(self.button_frame, text="Stop Monitoring", command=self.stop_monitoring,
                                         state="disabled")
        self.stop_button.pack(side="left", padx=(5, 0), expand=True)

        self.status_label = ctk.CTkLabel(self, text="Status: Stopped", anchor="w")
        self.status_label.pack(side="bottom", fill="x", padx=10, pady=5)

        self.process_queue()

    def start_monitoring(self):
        self.status_label.configure(text="Status: Starting...")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")

        self.stop_sniffing.clear()
        self.sniffing_thread = threading.Thread(target=self.sniffing_loop, daemon=True)
        self.sniffing_thread.start()
        self.status_label.configure(text=f"Status: Monitoring on {', '.join(INTERFACES)}")

    def stop_monitoring(self):
        self.status_label.configure(text="Status: Stopping...")
        self.stop_sniffing.set()
        if self.sniffing_thread and self.sniffing_thread.is_alive():
            self.sniffing_thread.join(timeout=2)
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_label.configure(text="Status: Stopped")

    def sniffing_loop(self):
        ip_data_store = defaultdict(lambda: {'ports': set(), 'first_seen': 0})

        def packet_handler(packet):
            try:
                if packet.haslayer(IP) and packet.haslayer(TCP):
                    src_ip = packet[IP].src
                    dst_port = packet[TCP].dport
                    tcp_flags = packet[TCP].flags

                    if 'S' in tcp_flags and 'A' not in tcp_flags:
                        current_time = time.time()

                        if ip_data_store[src_ip]['first_seen'] == 0 or (
                                current_time - ip_data_store[src_ip]['first_seen']) > TIME_WINDOW:
                            ip_data_store[src_ip]['first_seen'] = current_time
                            ip_data_store[src_ip]['ports'].clear()
                            ip_data_store[src_ip].pop('alerted', None)

                        ip_data_store[src_ip]['ports'].add(dst_port)
                        scanned_ports_count = len(ip_data_store[src_ip]['ports'])

                        if scanned_ports_count > PORT_SCAN_THRESHOLD:
                            if 'alerted' not in ip_data_store[src_ip]:
                                time_diff = current_time - ip_data_store[src_ip]['first_seen']

                                location = "Private IP"
                                reputation = "N/A"
                                if not ipaddress.ip_address(src_ip).is_private:
                                    location = get_ip_geolocation(src_ip)
                                    reputation = get_ip_reputation(src_ip, ABUSEIPDB_KEY)

                                alert_msg = (
                                    f"Port scan from IP: {src_ip} | "
                                    f"{scanned_ports_count} ports in {time_diff:.2f}s | "
                                    f"Location: {location} | "
                                    f"Reputation: {reputation}"
                                )
                                self.alert_queue.put(alert_msg)
                                logging.warning(alert_msg)
                                ip_data_store[src_ip]['alerted'] = True
            except Exception as e:
                logging.error(f"Error in packet_handler: {e}")

        try:
            sniff(iface=INTERFACES, prn=packet_handler, stop_filter=lambda p: self.stop_sniffing.is_set())
        except Exception as e:
            logging.error(f"Sniffing thread error: {e}")
            self.alert_queue.put(f"FATAL ERROR in sniffing thread: {e}")

    def process_queue(self):
        try:
            while not self.alert_queue.empty():
                message = self.alert_queue.get_nowait()
                timestamp = time.strftime('%H:%M:%S')

                self.alert_textbox.configure(state="normal")
                self.alert_textbox.insert("end", f"{timestamp} - {message}\n\n", "danger")
                self.alert_textbox.configure(state="disabled")
                self.alert_textbox.see("end")

                self.bell()

        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_queue)


# --- 5. Main Execution Block ---
if __name__ == "__main__":
    logging.info("Application starting...")
    app = IDS_GUI()
    app.mainloop()