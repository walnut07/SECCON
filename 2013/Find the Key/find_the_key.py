from scapy.all import *

# Read packets
packets = rdpcap('seccon_q1_pcap.pcap')
icmpdata = bytes(0)

# Extract ICMP data
for i in range(43, 48):
    p = packets[i]['Raw'].load
    icmpdata = icmpdata + p[28:]

index = icmpdata.find(b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a')
key = icmpdata[index:]

f = open('kagi.png', 'wb')
print(key)
f.write(key)
f.close()