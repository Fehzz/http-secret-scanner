from scapy.all import *
from scapy.layers.http import HTTP
from scapy.all import PcapReader, TCP, Raw
import re

packet = rdpcap("set5.pcap")

def PCAP_contains_HTTP(payload):
            search_patterns = b"Authorization|login|Login"
            match_patterns = re.search(search_patterns, payload)
            if match_patterns:
                  return True
            else:
                  return False
            
def PCAP_contains_FTP(payload):
            search_patterns = b"USER|PASS"
            match_patterns = re.search(search_patterns, payload)
            if match_patterns:
                  return True
            else:
                  return False
            
def PCAP_contains_IMAP(payload):
            search_patterns = b"[0-9] LOGIN"
            match_patterns = re.search(search_patterns, payload)
            if payload.startswith(b'*'):
                  return False
            if match_patterns:
                  return True
            else:
                  return False


def loop_through_PCAP(packet):
    for every_packet in packet:
        if every_packet.haslayer('Raw'):
            if every_packet.haslayer('TCP'):
                  tcp = every_packet['TCP']
                  raw_payload = every_packet['Raw'].load
                  decoded_payload = raw_payload.decode('utf-8', errors='ignore')    
                  if (tcp.sport == 80 or tcp.dport == 80) and PCAP_contains_HTTP(raw_payload):
                       print("HTTP credentials found:")
                       print(decoded_payload)
                  elif (tcp.sport == 21 or tcp.dport == 21) and PCAP_contains_FTP(raw_payload):
                      print(decoded_payload)
                  elif PCAP_contains_IMAP(raw_payload):
                      print("IMAP credentials found:")
                      print(decoded_payload)

loop_through_PCAP(packet)