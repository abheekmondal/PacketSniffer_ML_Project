import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QListWidget, QLabel
from PyQt5.QtCore import QThread
from scapy.all import sniff, IP, TCP, UDP, Raw  # Import necessary components from Scapy
from bpcktsniffer import start_biffing  # Import the packet sniffing function

class SniffThread(QThread):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self.running = True  # Flag to control sniffing

    def run(self):
        """Start sniffing packets and processing each one using the provided callback."""
        sniff(prn=self.packet_callback, filter="ip", store=0, count=0)

    def stop(self):
        """Stops the sniffing process by setting running to False."""
        self.running = False

    def packet_callback(self, packet):
        """Callback function to process each packet."""
        if self.running:
            if IP in packet:
                ip_layer = packet[IP]
                protocol = ip_layer.proto
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                # Determine the protocol name
                protocol_name = ""
                if protocol == 1:
                    protocol_name = f"ICMP: {protocol}"
                elif protocol == 6:
                    protocol_name = f"TCP: {protocol}"
                elif protocol == 17:
                    protocol_name = f"UDP: {protocol}"
                else:
                    protocol_name = f"Unknown Protocol: {protocol}"

                # TCP flags (only if the packet contains a TCP layer)
                if protocol == 6 and TCP in packet:
                    tcp_flags = packet[TCP].flags
                else:
                    tcp_flags = "N/A"

                # Packet information
                packet_info = {
                    'protocol': protocol_name,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'tcp_flags': tcp_flags
                }

                # Call the callback function with the packet information
                self.callback(packet_info)

class PacketSnifferApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Packet Sniffer')
        self.setGeometry(100, 100, 800, 400)

        # Create a horizontal layout for the entire window (left side blank)
        self.main_layout = QHBoxLayout()

        # Left side layout (keep it blank for now)
        self.left_layout = QVBoxLayout()
        self.main_layout.addLayout(self.left_layout, 1)  # Left side layout takes up 1 part (blank)

        # Right side layout (message label and packet display)
        self.right_layout = QVBoxLayout()

        # Label for instructions or status (on top of the packet display)
        self.label = QLabel('Press the button to start sniffing packets', self)
        self.right_layout.addWidget(self.label)

        # List widget to display captured packets
        self.packet_list_widget = QListWidget(self)
        self.packet_list_widget.setFixedWidth(280)  # Set a fixed width (35% of the window)
        self.right_layout.addWidget(self.packet_list_widget)

        # Add the right layout to the main layout
        self.main_layout.addLayout(self.right_layout, 3)  # Right side layout takes up 3 parts (sniffing area)

        # Add bottom layout for buttons below the sniffing message
        self.bottom_layout = QVBoxLayout()
        self.bottom_layout.setSpacing(10)  # Adjust the padding between buttons

        # Creating buttons
        self.start_button = QPushButton('Start Sniffing', self)
        self.start_button.clicked.connect(self.start_sniffing)
        self.apply_round_button_style(self.start_button)
        self.bottom_layout.addWidget(self.start_button)

        self.stop_button = QPushButton('Stop Sniffing', self)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)  # Disabled initially
        self.apply_round_button_style(self.stop_button)
        self.bottom_layout.addWidget(self.stop_button)

        self.clear_button = QPushButton('Clear', self)
        self.clear_button.clicked.connect(self.clear_packets)
        self.apply_round_button_style(self.clear_button)
        self.bottom_layout.addWidget(self.clear_button)

        # Add the bottom layout directly under the packet list
        self.right_layout.addLayout(self.bottom_layout)

        # Set the main layout to the window
        self.setLayout(self.main_layout)

        # Show the window
        self.show()

    def apply_round_button_style(self, button):
        """Apply a rounded style to a button."""
        button.setStyleSheet("""
            QPushButton {
                border-radius: 12px;
                background-color: #4CAF50;
                color: white;
                padding: 5px 15px;
                border: none;
                min-width: 100px;  /* Ensure a reasonable width for the button */
                text-align: center;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)

    def packet_callback(self, packet_info):
        """Callback function to handle each captured packet's info."""
        self.packet_list_widget.addItem(f"Protocol: {packet_info['protocol']}")
        self.packet_list_widget.addItem(f"Source IP: {packet_info['source_ip']}")
        self.packet_list_widget.addItem(f"Destination IP: {packet_info['destination_ip']}")
        self.packet_list_widget.addItem(f"TCP Flags: {packet_info['tcp_flags']}")
        self.packet_list_widget.addItem("-" * 50)

    def start_sniffing(self):
        """Start sniffing when the button is pressed."""
        self.label.setText('Sniffing packets...')
        self.start_button.setEnabled(False)  # Disable start button while sniffing
        self.stop_button.setEnabled(True)  # Enable stop button

        # Start a new thread for sniffing
        self.sniff_thread = SniffThread(self.packet_callback)
        self.sniff_thread.start()

    def stop_sniffing(self):
        """Stop sniffing when the stop button is pressed."""
        if self.sniff_thread:
            self.sniff_thread.stop()  # Stop the sniffing thread
            self.sniff_thread.terminate()  # Forcefully terminate the thread if necessary

        self.label.setText('Sniffing stopped.')
        self.start_button.setEnabled(True)  # Re-enable the start button
        self.stop_button.setEnabled(False)  # Disable the stop button

    def clear_packets(self):
        """Clear all previously sniffed packets."""
        self.packet_list_widget.clear()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    sniffer_app = PacketSnifferApp()
    sys.exit(app.exec_())
