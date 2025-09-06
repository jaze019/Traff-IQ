## Traff-IQ 🛡️
Your network's intelligent watchdog.

Traff-IQ is a lightweight, Python-based Intrusion Detection System (IDS) with a high "Traffic IQ." It provides intelligent, real-time monitoring of network activity to detect threats like port scans and other suspicious patterns. Each alert is automatically enriched with IP geolocation and reputation data, delivering actionable insights through a clean and modern graphical interface.

## Features
Real-Time Monitoring: Uses Scapy to sniff network packets on multiple interfaces simultaneously.

Intelligent Detection: A configurable, time-based threshold engine to accurately detect TCP SYN port scans.

Enriched Alerts: Automatically enhances alerts with IP geolocation (City, Country) and reputation scores from AbuseIPDB.

Modern GUI: A clean, responsive user interface built with CustomTkinter that displays alerts in real-time.

Noticeable Alerts: Critical alerts are displayed in a distinct color and trigger a system beep to ensure they are noticed.

Highly Configurable: All key settings (interfaces, thresholds, API keys) are managed in a simple config.ini file.

Persistent Logging: All events are logged to a file (ids.log) for later review.

## Tech Stack
Backend: Python 3

Packet Sniffing: Scapy

GUI: CustomTkinter

API Communication: Requests

Configuration: config.ini

## Setup and Installation
Follow these steps to get Traff-IQ running on your local machine.

### Prerequisites
This application is designed for Linux-based systems. You will need Python 3 and your system's package manager (apt, dnf, etc.).

### 1. Install System Dependencies
Tkinter is a system-level dependency required for the GUI.

#For Debian/Ubuntu-based systems:
sudo apt-get update
sudo apt-get install python3-tk

#For Fedora/CentOS-based systems:
sudo dnf install python3-tkinter

### 2. Set up the Python Environment
It's highly recommended to use a virtual environment.

# Create and activate the virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the required Python packages
pip install scapy requests customtkinter

## Configuration
Before running the application, you must configure it.

Rename the example config: cp config.example.ini config.ini

Edit config.ini:

interfaces: [A comma-separated list of network interfaces you want to monitor. #Find your interfaces by running ip a or ifconfig usually lo, ens33, eth0].

port_scan_threshold: The number of unique ports an IP must probe to trigger an alert.

time_window: The time in seconds within which the threshold must be reached.

abuseipdb_api_key: This is crucial. Sign up for a free account at AbuseIPDB to get your API key.

## Usage
Because packet sniffing requires elevated privileges, you must run the application with sudo, making sure to use the Python executable from within your virtual environment.

sudo ./venv/bin/python3 app.py

Once the application window appears, click "Start Monitoring" to begin sniffing. Alerts will appear in the text box in real-time.

## How It Works
Traff-IQ operates on a multi-threaded architecture to ensure the GUI remains responsive while sniffing packets in the background.

Main Thread: Runs the CustomTkinter GUI event loop (app.mainloop()).

Worker Thread: A separate thread is spawned to run the Scapy sniff() function. This thread performs the heavy lifting of packet capture and analysis.

Queue System: A thread-safe queue is used to pass alert messages from the worker thread back to the main GUI thread. This prevents race conditions and ensures smooth UI updates.

IP Intelligence: Upon detecting a potential threat, the worker thread makes API calls to ip-api.com and AbuseIPDB to gather additional context before sending the final, enriched alert to the GUI.
