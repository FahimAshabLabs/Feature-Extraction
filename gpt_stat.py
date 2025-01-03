# import dpkt
# from scapy.all import rdpcap, IP, TCP, UDP

# def analyze_pcap(file_path):
#     # Initialize variables
#     tcp_packets = 0
#     udp_packets = 0
#     unique_ports = set()
#     failed_connections = 0
#     repeated_ports = {}
    
#     # Open and parse pcap using dpkt
#     with open(file_path, 'rb') as f:
#         pcap = dpkt.pcap.Reader(f)
#         for timestamp, buf in pcap:
#             try:
#                 eth = dpkt.ethernet.Ethernet(buf)
#                 if isinstance(eth.data, dpkt.ip.IP):
#                     ip = eth.data
#                     if isinstance(ip.data, dpkt.tcp.TCP):
#                         tcp_packets += 1
#                         tcp = ip.data
#                         # Track destination ports
#                         unique_ports.add(tcp.dport)
#                         if not tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
#                             failed_connections += 1
#                         repeated_ports[tcp.dport] = repeated_ports.get(tcp.dport, 0) + 1
#                     elif isinstance(ip.data, dpkt.udp.UDP):
#                         udp_packets += 1
#                         udp = ip.data
#                         # Track destination ports
#                         unique_ports.add(udp.dport)
#                         repeated_ports[udp.dport] = repeated_ports.get(udp.dport, 0) + 1
#             except Exception as e:
#                 continue
    
#     # Calculate repeated connection attempts
#     repeated_connection_attempts = sum(count for count in repeated_ports.values() if count > 1)

#     # Load using scapy to ensure compatibility
#     packets = rdpcap(file_path)

#     # Output results
#     results = {
#         "TCP Packets Sent": tcp_packets,
#         "UDP Packets Sent": udp_packets,
#         "Number of Unique Ports Targeted": len(unique_ports),
#         "Failed Connection Attempts": failed_connections,
#         "Repeated Connection Attempts to Same Ports": repeated_connection_attempts
#     }
#     return results


# # Example usage
# file_path =  "/mnt/c/Network Security projects/wireshark/Dataset for esp and smart plug/attacksplug.pcap"#replace with the path to your pcap file
# #"C:\Network Security projects\wireshark\Dataset for esp and smart plug\attacksplug.pcap"
# features = analyze_pcap(file_path)
# for key, value in features.items():
#     print(f"{key}: {value}")



# import dpkt
# from scapy.all import rdpcap, Ether, IP, TCP, UDP

# def analyze_pcap(file_path):
#     # Initialize variables
#     tcp_packets = 0
#     udp_packets = 0
#     unique_ports = set()
#     unique_mac_addresses = set()
#     unique_ip_addresses = set()
#     failed_connections = 0
#     repeated_ports = {}
#     total_packets = 0
#     start_time = None
#     end_time = None

#     # Open and parse pcap using dpkt
#     with open(file_path, 'rb') as f:
#         pcap = dpkt.pcap.Reader(f)
#         for timestamp, buf in pcap:
#             try:
#                 total_packets += 1
#                 if start_time is None:
#                     start_time = timestamp
#                 end_time = timestamp

#                 eth = dpkt.ethernet.Ethernet(buf)
#                 unique_mac_addresses.update([eth.src, eth.dst])

#                 if isinstance(eth.data, dpkt.ip.IP):
#                     ip = eth.data
#                     unique_ip_addresses.update([ip.src, ip.dst])

#                     if isinstance(ip.data, dpkt.tcp.TCP):
#                         tcp_packets += 1
#                         tcp = ip.data
#                         # Track destination ports
#                         unique_ports.add(tcp.dport)
#                         if not tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
#                             failed_connections += 1
#                         repeated_ports[tcp.dport] = repeated_ports.get(tcp.dport, 0) + 1
#                     elif isinstance(ip.data, dpkt.udp.UDP):
#                         udp_packets += 1
#                         udp = ip.data
#                         # Track destination ports
#                         unique_ports.add(udp.dport)
#                         repeated_ports[udp.dport] = repeated_ports.get(udp.dport, 0) + 1
#             except Exception as e:
#                 continue

#     # Calculate repeated connection attempts
#     repeated_connection_attempts = sum(count for count in repeated_ports.values() if count > 1)
#     capture_duration = end_time - start_time if start_time and end_time else 0
#     packet_rate = total_packets / capture_duration if capture_duration > 0 else 0

#     # Output results
#     results = {
#         "TCP Packets Sent": tcp_packets,
#         "UDP Packets Sent": udp_packets,
#         "Number of Unique Ports Targeted": len(unique_ports),
#         "Failed Connection Attempts": failed_connections,
#         "Repeated Connection Attempts to Same Ports": repeated_connection_attempts,
#         "Total Packet Count": total_packets,
#         "Capture Duration (s)": capture_duration,
#         "Packet Rate (packets/s)": packet_rate,
#         "Number of Unique MAC Addresses": len(unique_mac_addresses),
#         "Number of Unique IP Addresses": len(unique_ip_addresses)
#     }
#     return results


# # Example usage
# file_path = "/mnt/c/Network Security projects/wireshark/Dataset for esp and smart plug/6normal.pcap"  # Replace with the path to your pcap file
# features = analyze_pcap(file_path)
# for key, value in features.items():
#     print(f"{key}: {value}")



#version3



import dpkt
from scapy.all import rdpcap, Ether, IP, TCP, UDP

def analyze_pcap(file_path):
    # Initialize variables
    tcp_packets = 0
    udp_packets = 0
    unique_ports = set()
    unique_ip_addresses = set()
    failed_connections = 0
    repeated_ports = {}
    total_packets = 0
    start_time = None
    end_time = None

    # Open and parse pcap using dpkt
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            try:
                total_packets += 1
                if start_time is None:
                    start_time = timestamp
                end_time = timestamp

                eth = dpkt.ethernet.Ethernet(buf)

                # Check if the Ethernet frame contains an IP packet
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    # Add unique IP addresses (both source and destination)
                    unique_ip_addresses.update([ip.src, ip.dst])

                    # Process TCP packets
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp_packets += 1
                        tcp = ip.data
                        # Track destination ports
                        unique_ports.add(tcp.dport)
                        if not tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
                            failed_connections += 1
                        repeated_ports[tcp.dport] = repeated_ports.get(tcp.dport, 0) + 1
                    # Process UDP packets
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp_packets += 1
                        udp = ip.data
                        # Track destination ports
                        unique_ports.add(udp.dport)
                        repeated_ports[udp.dport] = repeated_ports.get(udp.dport, 0) + 1
            except Exception as e:
                continue

    # Calculate repeated connection attempts
    repeated_connection_attempts = sum(count for count in repeated_ports.values() if count > 1)
    capture_duration = end_time - start_time if start_time and end_time else 0
    packet_rate = total_packets / capture_duration if capture_duration > 0 else 0

    # Output results
    results = {
        "TCP Packets Sent": tcp_packets,
        "UDP Packets Sent": udp_packets,
        "Number of Unique Ports Targeted": len(unique_ports),
        "Failed Connection Attempts": failed_connections,
        "Repeated Connection Attempts to Same Ports": repeated_connection_attempts,
        "Total Packet Count": total_packets,
        "Capture Duration (s)": capture_duration,
        "Packet Rate (packets/s)": packet_rate,
        "Number of Unique IP Addresses": len(unique_ip_addresses)
    }
    return results


# Example usage
file_path = "/mnt/c/Network Security projects/wireshark/Dataset for esp and smart plug/3hourstlstcpmqtt.pcap"  # Replace with the path to your pcap file
features = analyze_pcap(file_path)
for key, value in features.items():
    print(f"{key}: {value}")
