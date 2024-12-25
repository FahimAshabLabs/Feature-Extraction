
from scapy.all import*
import pandas as pd
import os
import numpy as np
import zipfile
import math
from scapy.all import rdpcap, IP, UDP, TCP, Raw, ARP, LLC, EAPOL
import time
def port_class(port):
    if 0 <= port <= 1023:
        return 1  # Well-known ports
    elif 1024 <= port <= 49151:
        return 2  # Registered ports
    elif 49152 <= port <= 65535:
        return 3  # Dynamic or private ports
    else:
        return 0  # Unknown port

# Shannon entropy function
def pre_entropy(payload):
    characters = []
    for i in payload:
        characters.append(i)
    return shannon(characters)

def shannon(data):
    freq_dict = {}
    for i in data:
        if i in freq_dict:
            freq_dict[i] += 1
        else:
            freq_dict[i] = 1    
    entropy = 0.0
    logarithm_base = 2
    payload_size = len(data)
    for key in freq_dict.keys():
        frequency = float(freq_dict[key]) / payload_size
        if frequency > 0: 
            entropy = entropy + frequency * math.log(frequency, logarithm_base)
    return -entropy

# Function to find all .pcap files in a directory
def find_the_way(path, extension):
    return [os.path.join(path, f) for f in os.listdir(path) if f.endswith(extension)]

# Define the folder structure for the dataset
dataset_name = ["Train.csv", "Validation.csv", "Test.csv"]
train, validation, test = [], [], []

# Split files into train, validation, and test sets
files_add = find_the_way("/mnt/c/Network Security projects/wireshark/test", '.pcap')  # Modify with your path
for ii, i in enumerate(files_add):
    train.append(i)

# Process the pcap files and extract features
for numero, dataset in enumerate([train, validation, test]):
    count = 0
    ths = open(dataset_name[numero], "w")
    header = "ARP,LLC,EAPOL,IP,ICMP,ICMP6,TCP,UDP,HTTP,HTTPS,DHCP,BOOTP,SSDP,DNS,MDNS,NTP,IP_padding,IP_add_count,IP_ralert,Portcl_src,Portcl_dst,Pck_size,Pck_rawdata,Label\n"
    ths.write(header)
    dst_ip_list = {}

    for i in dataset:
        filename = str(i).replace("\\", "/").split("/")
        #print(f"Processing file: {filename}")

        pkt = rdpcap(i)
        for jj, j in enumerate(pkt):
            # Initialize feature values
            ip_add_count = 0
            layer_2_arp = 0
            layer_2_llc = 0
            layer_3_eapol = 0        
            layer_3_ip = 0
            layer_3_icmp = 0
            layer_3_icmp6 = 0
            layer_4_tcp = 0
            layer_4_udp = 0
            layer_4_tcp_ws = 0
            layer_7_http = 0
            layer_7_https = 0
            layer_7_dhcp = 0
            layer_7_bootp = 0
            layer_7_ssdp = 0
            layer_7_dns = 0
            layer_7_mdns = 0
            layer_7_ntp = 0
            ip_padding = 0
            ip_ralert = 0
            port_class_src = 0
            port_class_dst = 0
            pck_size = 0
            pck_rawdata = 0
            entropy = 0
            layer_4_payload_l = 0

            try:
                pck_size = len(j) # Extract the packet size
            except Exception as e: 
                print(f"Error extracting packet size: {e}")

            try:
                if j.haslayer(IP):
                    layer_3_ip = 1     
                    temp = str(j[IP].dst)
                    if temp not in dst_ip_list.get(j.src, []):
                        dst_ip_list.setdefault(j.src, []).append(temp)
                    ip_add_count = len(dst_ip_list[j.src])
                    port_class_src = port_class(j[IP].sport)
                    port_class_dst = port_class(j[IP].dport)
            except Exception as e:
                print(f"Error processing IP layer: {e}")
            #print('xxxx')
            temp = str(j)
            if "ICMPv6" in temp:
                layer_3_icmp6 = 1

            try:
                if j.haslayer(IP) and j[IP].ihl > 5:
                    if IPOption_Router_Alert(j):  # Ensure this function is defined
                        pad = str(IPOption_Router_Alert(j).show())
                        if "Padding" in pad:
                            ip_padding = 1
                        ip_ralert = 1     
            except Exception as e:
                print(f"Error in IPOption Router Alert: {e}")

            if j.haslayer(ICMP):
                layer_3_icmp = 1

            if j.haslayer(Raw):
                pck_rawdata = 1

            if j.haslayer(UDP):
                layer_4_udp = 1
                if j[UDP].sport == 68 or j[UDP].sport == 67:
                    layer_7_dhcp = 1
                    layer_7_bootp = 1
                if j[UDP].sport == 53 or j[UDP].dport == 53:
                    layer_7_dns = 1
                if j[UDP].sport == 5353 or j[UDP].dport == 5353:
                    layer_7_mdns = 1
                if j[UDP].sport == 1900 or j[UDP].dport == 1900:
                    layer_7_ssdp = 1
                if j[UDP].sport == 123 or j[UDP].dport == 123:
                    layer_7_ntp = 1

            try:
                if j.haslayer(UDP) and j[UDP].payload:
                    layer_4_payload_l = len(j[UDP].payload)
            except Exception as e:
                print(f"Error processing UDP payload: {e}")

            if j.haslayer(TCP):
                layer_4_tcp = 1
                layer_4_tcp_ws = j[TCP].window
                if j[TCP].sport == 80 or j[TCP].dport == 80:
                    layer_7_http = 1
                if j[TCP].sport == 443 or j[TCP].dport == 443:
                    layer_7_https = 1
                try:
                    if j[TCP].payload:
                        layer_4_payload_l = len(j[TCP].payload)
                except Exception as e:
                    print(f"Error processing TCP payload: {e}")

            if j.haslayer(ARP):
                layer_2_arp = 1

            if j.haslayer(LLC):
                layer_2_llc = 1

            if j.haslayer(EAPOL):
                layer_3_eapol = 1

            try:
                if j.haslayer(Raw):
                    entropy = pre_entropy(j[Raw].original)
            except Exception as e:
                print(f"Error calculating entropy: {e}")

            # Label can be assigned based on other features or left as "Unknown"
            label = "Unknown"

            line = [
                layer_2_arp, layer_2_llc, layer_3_eapol, layer_3_ip, layer_3_icmp, layer_3_icmp6, 
                layer_4_tcp, layer_4_udp,layer_7_http, layer_7_https, layer_7_dhcp, 
                layer_7_bootp, layer_7_ssdp, layer_7_dns, layer_7_mdns, layer_7_ntp, ip_padding, ip_add_count, 
                ip_ralert, port_class_src, port_class_dst, pck_size, pck_rawdata, label
                #label, filename[2], filename[3][:-5],entropy,layer_4_payload_l,layer_4_tcp_ws,
                
            ]

            ths.write(",".join([str(i) for i in line]) + "\n")
            #print(f"Processed packet {jj+1}/{len(pkt)}")

        count += 1
    ths.close()
