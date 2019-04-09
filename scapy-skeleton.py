#! /usr/bin/env python3

from scapy.all import *
from sys import *
import socket 
import os
from collections import Counter
    
def fields_extraction(packet):
    print(packet.sprintf("{IP:%IP.src%,%IP.dst%,}"
        "{TCP:%TCP.sport%,%TCP.dport%,}"
        "{UDP:%UDP.sport%,%UDP.dport%}"))

    print(packet.summary())

    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    cPackets.update([key])
    print(f'Packet #{sum(cPackets.values())}: {packet[0][1].src} ==> {packet[0][1].dst}')

    packet.show()

    #use x.time for time information on the pkts

# create packet counter
cPackets = Counter()


# Use sniff function to start sniffing packets.
# The information you can get from each sniffed packet are:
#   - Ethernet header: dst, src, type;
#   - IP header: version, ihl, tos, len, if, flags, frag, ttl, proto, chksum, src, dest;
#   - TCP header: sport, dport, seq, ack, dataofs, reserved, flags, window, chksum, urgptr, options;
#   - UDP header: sport, dport, len, chksum;
#   - Occasionally some other protocol might show up, such as ARP, which is a transport layer protocol.
pkts = sniff(prn = fields_extraction, count = 10)

# print pkts[0].show()

# TO DO: Detect network "flows" among the sniffed packets.
#       Flows are defined by the tuple (src IP address, src port, dest IP address, dest port, transport protocol).
#       The transport protocol is either TCP or UDP.
#       You can assign to each flow an ID, which is shared among all packets of that flow.

