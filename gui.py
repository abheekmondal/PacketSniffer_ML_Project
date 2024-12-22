import sys
#import threading
from PyQt5.QtCore import QThread, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QListWidget, QLabel, QSlider
from spcktsniffer import start_sniffing  # Import the sniffing function from your Simple sniffer module
from bpcktsniffer import start_biffing  # Import the sniffing function from Browser sniffer module


class SniffThread(QThread):
    def __init__(self, packet_callback, mode):
        super().__init__()
        self.packet_callback = packet_callback
        self.mode = mode
        self.sniffing = True

    def stop(self):
        """Set the flag to stop sniffing."""
        self.sniffing = False
        
    def run(self):
        """Start sniffing in the selected mode."""
        if self.mode == 'S':
            start_sniffing(self.packet_callback)  # Simple sniffer
        elif self.mode == 'B':
            start_biffing(self.packet_callback)  # Browser sniffer
        else:
            print("Something went wrong")

    

    

class PacketSnifferApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.sniffing_mode = 'S'  # Default to Simple mode (S)
        self.sniff_thread = None  # Initialize sniffing thread as None

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
        self.packet_list_widget.setFixedWidth(580)  # Set a fixed width (35% of the window)
        self.right_layout.addWidget(self.packet_list_widget)

        # Add the right layout to the main layout
        self.main_layout.addLayout(self.right_layout, 3)  # Right side layout takes up 3 parts (sniffing area)

        # Add top slider to control the packet display mode
        self.slider_label = QLabel('Simple      |       Browser', self)
        self.right_layout.addWidget(self.slider_label)

        # Create a custom toggle slider (from 0 to 1, representing Simple and Browser)
        self.slider = QSlider(Qt.Horizontal, self)
        self.slider.setRange(0, 1)  # Range from 0 (Simple) to 1 (Browser)
        self.slider.setValue(0)  # Start with Simple mode
        self.slider.setFixedWidth(120)  # Make the slider width smaller
        self.slider.setStyleSheet(
            """
             QSlider::groove:horizontal {
                border: 1px solid #999999;  /* Light gray border for the groove */
                background: #d0d0d0;  /* Light gray background for the groove */
                height: 8px;  /* Set the height of the groove */
                border-radius: 20px;  /* Rounded corners for the groove */
            }
    
            QSlider::handle:horizontal {
                background: #ffffff;  /* White background for the slider handle */
                border: 2px solid #666666;  /* Dark gray border for the handle */
                width: 3px;  /* Width of the handle */
                height: 8px;  /* Height of the handle */
                border-radius: 10px;  /* Fully rounded handle */
                margin-top: -6px;  /* Adjust vertical position of the handle */
                margin-bottom: -6px;  /* Adjust vertical position of the handle */
            }
    
            QSlider::handle:horizontal:pressed {
                background: #4CAF50;  /* Green background when the handle is pressed */
            }
            """    
        )  # Custom style for the slider
        
        self.slider.valueChanged.connect(self.update_mode)  # Connect slider value change to update mode
        self.right_layout.addWidget(self.slider)

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

    def update_mode(self):
        """Update the mode based on the slider value (S for Simple, B for Browser)."""
        if self.slider.value() == 0:
            self.sniffing_mode = 'S'  # Simple mode
        else:
            self.sniffing_mode = 'B'  # Browser mode

    def packet_callback(self, packet_info):
        """Callback function to handle each captured packet's info."""
        if self.sniffing_mode == 'S':
            # Show minimal details in Simple mode
            display_info = f"Protocol: {packet_info['protocol']}\nSource IP: {packet_info['source_ip']}\nDestination IP: {packet_info['destination_ip']}\nTCP Flags: Flag {packet_info['tcp_flags']}"
        elif self.sniffing_mode == 'B':
            # Show detailed packet info in Browser mode
            display_info = f"Protocol: {packet_info['protocol']}\nSource IP: {packet_info['source_ip']}\nDestination IP: {packet_info['destination_ip']}\nTCP Flags: Flag {packet_info['tcp_flags']}\nRaw Data: {packet_info['packet']}"
        
        # Display the packet info in the list widget
        self.packet_list_widget.addItem(display_info)
        self.packet_list_widget.addItem("-" * 50)

    def start_sniffing(self):
        """Start sniffing when the button is pressed."""
        self.label.setText('Sniffing packets...')
        self.start_button.setEnabled(False)  # Disable start button while sniffing
        self.stop_button.setEnabled(True)  # Enable stop button

        # Start the sniffing process in a new thread
        self.sniff_thread = SniffThread(self.packet_callback, self.sniffing_mode)
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