from  scapy.all import *
from httpRequest import parse
import requests
from scapy.layers.inet import IP, TCP
from scapy.layers import http
from scapy.layers.http import HTTPRequest
#etherLayer = Ether(src=get_if_hwaddr(self.networkInterface), dst=pkt[Ether].src)
#ipLayer = IP(src=pkt[IP].src, dst=pkt[IP].src)
#tcpLayer = TCP(sport=8053, dport=1066, seq=1, ack=1)


def process_packet(pkt):
    if pkt[TCP].flags == 'S':
        print("starting handshake")
        etherLayer = Ether(src=get_if_hwaddr("enp0s3"), dst=pkt[Ether].src)
        ipLayer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        tcpLayer = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="SA", ack = pkt[TCP].seq + 1, seq = pkt[TCP].ack)
        ackpkt = etherLayer / ipLayer / tcpLayer
        sendp(ackpkt, verbose=0, iface='enp0s3')


    if pkt.haslayer(Raw) and pkt[IP].src == "192.168.56.101":
        data = str(pkt[Raw])
        headers, req, getreq = parsereq(data)


        request = requests.get("https://" + req + getreq, verify=False, headers=headers)
        sendpkt(pkt, parse(request))


def parsereq(data):
    req = {}
    targeturl = ""
    getreq = ""
    datasplit = data.split("\\r\\n")
    #datasplit[0] = 'GET / HTTP/1.1'
    #print(datasplit[0][6:len(datasplit[0])-9])
    datasplit[-1] = ''
    for i in datasplit:
        newi = i.split(": ")
        if newi[0][2:5] == "GET":
            getreq = datasplit[0][6:len(datasplit[0])-9]
        elif newi[0] == "Host":
            targeturl = targeturl + newi[1]
        else:
            if newi[0] != ""and newi[0][0] != 'b':
                print(newi[0])
                req[newi[0]] = newi[1]

    return req, targeturl, getreq


def sendpkt(pkt, response):
    etherLayer = Ether(src=get_if_hwaddr("enp0s3"), dst=pkt[Ether].src)
    ipLayer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    tcpLayer = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, ack = pkt[TCP].seq + 1, seq = pkt[TCP].ack, flags="FA")
    response2 = "HTTP/1.1 401\r\n" \
               "WWW-Authenticate: Basic realm='Test'" \
               "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" \
               "Server: Apache/2.2.14 (Win32)\r\n" \
               "Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\n" \
               "Accept-Ranges: bytes\r\n" \
               "Content-Length: 48\r\n" \
               "Keep-Alive: timeout=15, max=100\r\n" \
               "Connection: Keep-Alive\r\n" \
               "Content-Type: text/html\r\n\n" \
               "no auth header received\r\n\r\n"

    newpkt = etherLayer / ipLayer / tcpLayer / response

    sendp(newpkt, verbose=0, iface="enp0s3")


sniff(filter="port 8050",prn=process_packet, iface="enp0s3")