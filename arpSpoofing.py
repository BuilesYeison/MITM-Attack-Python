#!/usr/bin/env python
#_*_ coding: utf8 _*_
#code by https://www.youtube.com/watch?v=LYodfr9dl8o&t=113s

#Instructions:
#See help: python3 arpSpoofing.py --help , and you can see the info that the script need to execute
#Range: ifconfig and the range is ej: 192.162.1.1/24 and the gateway: 192.168.1.1
#set: python 4 arpSpoofing.py -r 192.162.1.1/24 -g 192.168.1.1

from scapy.all import *
from colorama import Fore, init
import argparse
import sys

init() #init colorama

parse = argparse.ArgumentParser()#receive arguments through the command line
parse.add_argument("-r", "--range",help="Rango a escanear o spoofear")
parse.add_argument("-g", "--gateway",help="Gateway/puerta de enlace/router")
parse=parse.parse_args()#established arguments

def getMac(gateway):#obtain the gateway/router mac address
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

def restoreArp(destip, sourceip,hwsrc,hwdst):#restore arp tables para evitar que los dispositivos no se queden sin internet
    pass

def arpSpoofing(hwdst, pdst, psrc):#spoof all the devices connected in the same red
    pass

def main():
    if parse.range and parse.gateway: #if the user insert correctly the options (range and gateway)
        macGateway = getMac(parse.gateway) #get the router mac with the option of the user
        print(macGateway)
        scannerNet(parse.range, parse.gateway)
    else:
        print("Set info please")

if __name__ == "__main__":
    main()