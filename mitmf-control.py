from scapy.all import *
import socket
from python_arptable import *
import netifaces,sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
mylocalip = s.getsockname()[0]
s.close()

def alarm(a):
	while True:
		print("YOU ARE IN MITM ATTACK !!! ATTACKER : ",a)

def arptable():
	a = get_arp_table()
	arp_liste = {}
	for i in range(len(a)):
		arp_liste.update({a[i]['IP address'] : a[i]['HW address']})
	return arp_liste
interfaces = netifaces.interfaces()
iface = netifaces.gateways()['default'][2][1]
a = interfaces.index(iface)
gtw_ip = netifaces.gateways()['default'][2][0]
gtw_mac = arptable()[gtw_ip]
print("gtw_ip : ",gtw_ip,"-------- gtw_mac : ",gtw_mac)
net_info = netifaces.ifaddresses(interfaces[a]).setdefault(netifaces.AF_PACKET)
my_mac = net_info[0]["addr"]


def yaz(packet):
	if packet[ARP].psrc == gtw_ip and packet[ARP].hwsrc != gtw_mac and packet[ARP].hwdst == my_mac and packet[ARP].pdst == mylocalip:
		alarm(packet[ARP].hwsrc)


while True:
	sniff(filter="arp",prn=yaz,count=1)
	print("*")