from scapy.all import *

# Replace <Windows_IP> with the IP address of the Windows machine
windows_ip = "192.168.37.148" #IP of my ubuntu machine.

# Craft HTTP GET request with redirect link
http_request = Ether()/IP(dst=windows_ip)/TCP(dport=80)/("GET / HTTP/1.1\r\n"
"Host: " + windows_ip + "\r\n"
"Connection: keep-alive\r\n"
"Upgrade-Insecure-Requests: 1\r\n"
"Cache-Control: max-age=0\r\n"
"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Accept-Language: en-US,en;q=0.9\r\n"
"Referer: http://" + windows_ip + "/\r\n"
"Location: http://debika's_melicious_website.com\r\n\r\n")

# Send HTTP request
sendp(http_request, iface="wlp2s0")
