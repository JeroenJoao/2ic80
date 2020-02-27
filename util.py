from scapy.all import *

# networkInterface = "enp0s3"

# ipunt :
# - ip as str
# - network interface ast str
# output :
# - MAC adress which correspondes to the IP OR
# - None is there if no devices in the network with requested IP
def getMAC(ip, networkInterface):

    #create ARP/Ether() packet
    #whcih will ask whole network who has such ip
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = ether / arp

    #send that packet on the network and wait for the response
    result = srp(pkt, iface=networkInterface, timeout=2, inter=0.1)[0]

    #initialise output
    output = None

    #save received hardware address if exist to output variable
    for sent, received in result:
        print ("Requested ip : "+received.psrc+" has MAC :"+ received.hwsrc)
        output = received.hwsrc



    return output

# getMAC("192.168.56.101", networkInterface)