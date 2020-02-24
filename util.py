from scapy.all import *

# networkInterface = "enp0s3"

def getMAC(ip, networkInterface):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = ether / arp
    result = srp(pkt, iface=networkInterface, timeout=2, inter=0.1)[0]
    output = None
    for sent, received in result:
        print ("Requested ip : "+received.psrc+" has MAC :"+ received.hwsrc)
        output = received.hwsrc



    return output

# getMAC("192.168.56.101", networkInterface)