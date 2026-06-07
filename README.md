# HTTP Credential Extractor

A Scapy-based tool to extract HTTP Basic Authentication credentials from PCAP files. Designed to be extended for additional credential types in the future.



## What I Learned Building This

**Binary Files & rdpcap**

Initially, I got a UnicodeDecodeError trying to read the PCAP directly. I realized PCAPs are binary files, which is why I needed Scapy's `rdpcap()` function to open and parse them properly.

**Packet Layer Structure**

Understanding how packet data is nested was also important. Learning to extract the Raw layer using `every_packet['Raw'].load` gave me access to the actual payload data to analyze.

**Regex on Bytes**

Searching for patterns in network traffic means working with bytes, not strings. `re.search(b"pattern", payload)` matches byte patterns directly in the raw payload.

**Multiple Patterns**

Using `b"PATTERN1|PATTERN2"` syntax lets me search for multiple keywords in one regex call, making detection cleaner.

**Decoding Bytes to Strings**

`.decode('utf-8', errors='ignore')` converts raw bytes into readable text. The `errors='ignore'` parameter is important in case binary data contains invalid UTF-8, in which case we need to ignore those errors to prevent crashes.

**Port vs Protocol Detection**

I did not like the idea of Port based detection because HTTP traffic could be on any arbitrary port like 8000 or 8080 etc rather than 80. Protocol-based detection (actually looking for HTTP headers) is more reliable.

**Basic Auth Decoding**

HTTP Basic auth uses base64-encoded credentials in the format `username:password`. Decoding the Authorization header and splitting on `:` extracts the actual credentials.
