from scapy.all import *

attackerIP = "192.168.56.103"
victimIP = "192.168.56.101"

arp = ARP(pdst = victimIP)
ether = Ether(dst= "ff:ff:ff:ff:ff:ff")
pkt = ether/arp
networkInterface = "enp0s3"
clients = []

result = srp(pkt, iface = networkInterface, timeout = 2 , inter = 0.1)[0]


for sent, received in result :
    clients.append({"ip" : received.psrc, "mac" : received.hwsrc})

for client in clients :
    print("{:16}   {}".format(client["ip"], client["mac"])) 
