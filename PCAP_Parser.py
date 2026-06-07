#Imported Scapy
#Encountered a rookie error: UnicodeDecodeError: 'charmap' codec can't decode byte 0x8d in position 5087: character maps to <undefined> when trying to print the pcap for testing the first time
#Realise PCAPs are binary so that's where i would need Scapy's rdpcap function to open the file in order to read it


from scapy.all import *
from scapy.layers.http import HTTP
import re

packets = rdpcap("set5.pcap")

def find_secrets_in_http(packets):
        for every_line in packets:
                if every_line.haslayer('HTTP'):
                        raw_payload = every_line['HTTP'].load
                        search_patterns = b"LOGIN|PASSWORD|USER|PASS|AUTH|IMAP|FTP"
                        match = re.search(search_patterns,raw_payload)
                        if match:
                                decoded = raw_payload.decode('utf-8', errors='ignore')
                                if "LOGIN" in decoded:
                                        print(decoded)

find_secrets_in_http(packets)
