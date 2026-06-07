#Imported Scapy
#Encountered a rookie error: UnicodeDecodeError: 'charmap' codec can't decode byte 0x8d in position 5087: character maps to <undefined> when trying to print the pcap for testing the first time
#Realised PCAPs are binary so that's where i would need Scapy's rdpcap function to open the file in order to read it


from scapy.all import *
from scapy.layers.http import HTTP
import re
import base64

packets = rdpcap("set5.pcap")

def find_secrets_in_http(packets):
        last_seen = ""
        for every_line in packets:
                if every_line.haslayer('HTTP'):
                        raw_payload = bytes(every_line['HTTP'])
                        search_patterns = b"Authorization|token|bearer"
                        match = re.search(search_patterns,raw_payload)
                        if match:
                                decoded = raw_payload.decode('utf-8', errors='ignore')
                                #print(decoded)
                                
                                for every_line in decoded.splitlines():
                                        if "Authorization: Basic" in every_line:
                                                token = base64.b64decode(every_line.split()[2])
                                                decoded_bytes = token.decode('utf-8')
                                                if decoded_bytes != last_seen:
                                                        split_username_and_password = decoded_bytes.split(':')
                                                        print(f"[+] ALERT. Leaked Credentials Found! -> User: {split_username_and_password[0]} | Pass: {split_username_and_password[1]}")
                                                        last_seen = decoded_bytes

find_secrets_in_http(packets)
