from scapy.all import *

conf.use_pcap = True

def findSeqNum(pkt):
	global seq_num
	seq_num = pkt[TCP].ack
# TCP-Flags (found by Youssef Charif and taken from https://stackoverflow.com/questions/38803392/scapy-sniff-filter-tcp-with-syn-ack)
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
#Setting the values that will be used in the spoofed packet (used from attack code: Samer Hanna)
ip_src = input("[*] Enter source ip: ")
ip_dst = input("[*] Enter destination ip: ")
port_src = int(input("[*] Enter source port: "))
port_dst = int(input("[*] Enter destination port: "))

#Sniffing a packet sent from dst to src, in order to get seq_num from the packet's ack (used from attack code: Samer Hanna)
cap_filter = "dst host " + ip_src + " and dst port " + str(port_src)
#edited from the attack code by Youssef Charif
#showing both methods of finding RST packets by Youssef Charif and Mariam Termos collaboratively 
#first method: pktsFiltered: we filter the packets with the RST flag and return in pktsFiltered a list of such packets on the network
#between source and destination IP addresses
#lfilter parameter code taken from https://stackoverflow.com/questions/38803392/scapy-sniff-filter-tcp-with-syn-ack
pktsFiltered = sniff(filter=cap_filter, count=100, lfilter = lambda x: x.haslayer(TCP) and x[TCP].flags & RST and x[TCP].flags & ACK)
#second method: pktsUnfiltered: we filter packets sent between source and destination only, without the lfilter parameter
pktsUnfiltered=sniff(filter=cap_filter, count=100)
#looping over each packet in the pktsUnfiltered list and manually checking for the flag of each packet
RSTcount=0 #counter for packets with RST flag
SusNumber=15 #number of RST packets where we conclude that the attack is going on 
#checking for RST flag code done by Youssef Charif and Mariam Termos collaboratively 
#syntax for checking TCP flag taken from : https://stackoverflow.com/questions/20429674/get-tcp-flags-with-scapy
for i in range(100):
    if (pktsUnfiltered[i]['TCP'].flags==RST): #add to the counter if we find the RST flag
        count+=1
    if (count>=SusNumber):
        print("Detection of TCP RST attack!")
        break #print warning and break the loop when we are sure that the attack is being executed
