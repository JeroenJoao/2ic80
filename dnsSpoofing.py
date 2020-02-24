from scapy.all import *
import util

networkInterface = "enp0s3"

victimIP = "192.168.56.101"
victimMAC = "08:00:27:b0:a1:ab"

serverIP = "192.168.56.102"
serverMAC = "08:00:27:c6:a4:61"

attackerIP = get_if_addr(networkInterface)
attackerMAC = get_if_hwaddr(networkInterface)

def dnsSpoof():
    dns_req = Ether() / IP( dst = victimIP, src = attacketIP)
    dns_req = dns_req/Udp(port = 53)