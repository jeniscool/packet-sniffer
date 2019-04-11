#! /usr/bin/env python3

from scapy.all import *
from sys import *
import socket 
import os
import numpy as np
from collections import Counter
import csv


# **********************************
# Classes to store packet data
# **********************************
#   - Ethernet header: dst, src, type;
class Ethernet:

    def __init__(self, dst, src, p_type):
        self.dst = dst
        self.src = src
        self.p_type = p_type


#   - IP header: version, ihl, tos, len, if, flags, frag, ttl, proto, chksum, src, dest;
class IP:

    def __init__(self, v, ihl, tos, len, id, flags, frag, ttl, proto, chksum, src, dest):
        self.v = v
        self.ihl = ihl
        self.tos = tos
        self.len = len
        self.id = id
        self.flags = flags
        self.frag = frag
        self.ttl = ttl
        self.proto = proto
        self.chksum = chksum
        self.src = src
        self.dest = dest


#   - TCP header: sport, dport, seq, ack, dataofs, reserved, flags, window, chksum, urgptr, options;
class TCP:

    def __init__(self, sport, dport, seq, ack, dataofs, reserved, flags, window, chksum, urgptr, options):
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.dataofs = dataofs
        self.reserved = reserved
        self.flags = flags
        self.window = window
        self.chksum = chksum
        self.urgptr = urgptr
        self.options = options


#   - UDP header: sport, dport, len, chksum;
class UDP:

    def __init__(self, sport, dport, len, chksum):
        self.sport = sport
        self.dport = dport
        self.len = len
        self.chksum = chksum

#   - Occasionally some other protocol might show up, such as ARP, which is a transport layer protocol.


flow1 = []
flow2 = []
flow3 = []
flow4 = []
flow5 = []
flow6 = []
flow7 = []
flow8 = []

# **********************************
# Function to pull data from packets
# **********************************
def fields_extraction(packet):
    for i in range(8):
        if not flow1:



    pEther.append(packet)


    # Fill classes
#    pEther[sum(cPackets.values())] = Ethernet(packet[0][0].dst, packet[0][0].src, hex(packet[0][0].type))
#    pIP[sum(cPackets.values())] = IP(packet[0][1].version, packet[0][1].ihl, packet[0][1].tos, packet[0][1].len,
#                                     packet[0][1].id, packet[0][1].flags, packet[0][1].frag, packet[0][1].ttl,
#                                     packet[0][1].proto, packet[0][1].chksum, packet[0][1].src, packet[0][1].dst)
#
#    pTCP[sum(cPackets.values())] = TCP(packet[0][2].sport, packet[0][2].dport, packet[0][2].seq, packet[0][2].ack,
#                                       packet[0][2].dataofs, packet[0][2].reserved, packet[0][2].flags,
#                                       packet[0][2].window, packet[0][2].chksum, packet[0][2].urgptr,
#                                       packet[0][2].options)

    # use packet.time for time information on the pkts


# **********************************
# Function to fill csv with packet data
# **********************************
# def fill_csv():
#    with open('packet-data.csv', mode='w') as csvfile:
        # print("hi")
        # pd-writer = csv.writer(pd, deliminator = ',', quotechar = '"')
#        fieldNames = ['flow_id', 'feature_1', 'feature_2', 'feature_3', 'feature_4', 'label']

# create packet counter
# cPackets = Counter()

# variable for count
c = 1000

# Use sniff function to start sniffing packets.
pkts = sniff(prn=fields_extraction, count=c)
#pkts = sniff(count=c)


tempProto = pkts[0][1].proto
tempSrc = pkts[0][1].src
tempDst = pkts[0][1].dst
tempSport = pkts[0][2].sport
tempDport = pkts[0][2].dport

for i in range(c):
    # print(pkts[i][1].proto)
    if pkts[i][1].proto == tempProto and pkts[i][1].src == tempSrc and \
            pkts[i][1].dst == tempDst and pkts[i][2].sport == tempSport and pkts[i][2].dport == tempDport:
        print("hi")





#pEther[0].show()

# fill_csv()

# print(pEther)

# print(pkts[9].show())

# TO DO: Detect network "flows" among the sniffed packets.
#       Flows are defined by the tuple (src IP address, src port, dest IP address, dest port, transport protocol).
#       The transport protocol is either TCP or UDP.
#       You can assign to each flow an ID, which is shared among all packets of that flow.

