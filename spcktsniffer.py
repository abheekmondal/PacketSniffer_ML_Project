from scapy.all import sniff, Raw, IP
from scapy.layers.inet import TCP, UDP, ICMP

def start_sniffing(callback):
    """
    Starts sniffing network packets and processes each packet using the provided callback function.
    """
    def packet_callback(packet):
        if IP in packet:
            ip_layer = packet[IP]
            protocol = ip_layer.proto
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # Determine the protocol
            protocol_name = ""
            if protocol == 1:
                protocol_name = f"ICMP: {ip_layer.proto}"
            elif protocol == 6:
                protocol_name = f"TCP: {ip_layer.proto}"
            elif protocol == 17:
                protocol_name = f"UDP: {ip_layer.proto}"
            else:
                protocol_name = f"Unknown Protocol: Flag {ip_layer.proto}"

            # TCP flags (only if the packet contains a TCP layer)
            if protocol == 6 and TCP in packet:
                tcp_flags = packet[TCP].flags
            else:
                tcp_flags = "N/A"

            # Display basic packet information
            packet_info = {
                'protocol': protocol_name,
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'tcp_flags': tcp_flags
            }

            # Call the callback function with the packet details
            callback(packet_info)
            
            #print the detailed structure of the packet
            #packet.show()
            #print("-" * 50)

    # Capture packets on the default network interface
    sniff(prn=packet_callback, filter="ip", store=0, count=0)


# This is a basic example of what the callback function might look like.
# This function will be called every time a packet is captured.
def packet_info_callback(packet_info):
    print(f"Protocol: {packet_info['protocol']}")
    print(f"Source IP: {packet_info['source_ip']}")
    print(f"Destination IP: {packet_info['destination_ip']}")
    print(f"TCP Flags: {packet_info['tcp_flags']}")
    print("-" * 50)

if __name__ == "__main__":
    start_sniffing(packet_info_callback)
