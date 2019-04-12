#! /usr/bin/env python3

from scapy.all import *
from sys import *
import socket 
import os
import numpy as np
from collections import Counter
import csv

# **********************************
# Classes to store packet data - don't delete yet
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
        self.len = len # average size of exchanged packets??
        self.id = id
        self.flags = flags
        self.frag = frag
        self.ttl = ttl
        self.proto = proto
        self.chksum = chksum
        self.src = src
        self.dest = dest


# ****** TCP header: sport, dport, seq, ack, dataofs, reserved, flags, window, chksum, urgptr, options ******
# Used for reliable connections
# Checks for: lost packets, transmission errors, packets out of order and so on....
# examples: emails, sms, internet browsing
# Transportation Layer
# ****************************************
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


# ****** UDP header: sport, dport, len, chksum ******
# Used for unreliable connections with no sessions
# Does not check for error checking or flow control
# Sends packets and forgets
# examples:voice over IP, video streaming
# Transportation Layer
# ***************************************************
class UDP:

    def __init__(self, sport, dport, len, chksum):
        self.sport = sport
        self.dport = dport
        self.len = len
        self.chksum = chksum

#   - Occasionally some other protocol might show up, such as ARP, which is a transport layer protocol.


# **********************************
# Function to pull data from packets and put in a dictionary
# **********************************
def fields_extraction(packet):

    # Fill classes
    # pEther[sum(cPackets.values())] = Ethernet(packet[0][0].dst, packet[0][0].src, hex(packet[0][0].type))
    # pIP[sum(cPackets.values())] = IP(packet[0][1].version, packet[0][1].ihl, packet[0][1].tos, packet[0][1].len,
    #                                 packet[0][1].id, packet[0][1].flags, packet[0][1].frag, packet[0][1].ttl,
    #                                 packet[0][1].proto, packet[0][1].chksum, packet[0][1].src, packet[0][1].dst)
    #
    # pTCP[sum(cPackets.values())] = TCP(packet[0][2].sport, packet[0][2].dport, packet[0][2].seq, packet[0][2].ack,
    #                                   packet[0][2].dataofs, packet[0][2].reserved, packet[0][2].flags,
    #                                   packet[0][2].window, packet[0][2].chksum, packet[0][2].urgptr,
    #                                   packet[0][2].options)

    # use packet.time for time information on the pkts
    packet.show()


# **********************************
# Function to find flows and place them in a dictionary
# **********************************
def find_flows():
    # for all packets found, group them into flows
    for packet in packets:
        # a flow is a tuple consisting of: [srcIP addr, srcport, destIP addr, destport, tranproto]
        # assign to each flow an ID, which is shared among all packets of that flow.
        # if hasattr(packet.payload, "src") and hasattr(packet.payload, "proto"):
        ID = (packet[0][1].src, packet[0][2].sport, packet[0][1].dst, packet[0][2].dport, packet[0][1].proto)

        if ID in flows:  # append packet to flow, if already exists
            flows[ID].append(packet)
        else:  # else check for bi-directional flows
            # represents the bi-directional flow
            bi_ID = (packet[0][1].dst, packet[0][2].dport, packet[0][1].src, packet[0][2].sport, packet[0][1].proto)
            if bi_ID in flows:  # if that's in the packet, append
                flows[bi_ID].append(packet)
            else:  # if not, create a new flow in dictionary
                flows[ID] = [packet]


# *********************************
# Function to extract data from flows into csv
# *********************************
def extract_data():
    csv_file = 'test.csv'
    with open(csv_file, 'w') as p:
        # write csv headers
        p.write(str('num packets, proto, avg packet size\n'))

        # for each flow
        for key in flows.keys():
            # finds number of packets in each flow
            flow_size = len(flows[key])
            # flows[key][0].show()
            print(" flow size: %d\n" % flow_size)
            # finds average packet size
            total_size = 0
            for f in range(flow_size):
                # print(flows[key][f].summary())
                total_size = total_size + flows[key][f][1].len
                print(" packet size is %f\n" % flows[key][f][1].len)
                print("total size is %f\n" % total_size)
            avg_packet_size = total_size/flow_size
            print("avg packet size %f\n" % avg_packet_size)
            # finds protocol for each flow
            if flows[key][0][1].proto == 17:  # UDP = 17
                protocol = 1
            elif flows[key][0][1].proto == 6:  # TCP = 6
                protocol = 0
            else:
                protocol = 2

            # write data to csv
            writer = csv.writer(p, delimiter=',')
            writer.writerows(zip("%.2f" % flow_size, "%d" % protocol, "%.2f" % avg_packet_size))


# *********************************
# Start Program!
# ********************************
# Why do we need this counter?
cPackets = Counter()  # packet counter
c = 1000  # variable for amount of packets to collect
packets = sniff(count=c)
# might need numpy arrays to hold features in classes
flows = {}  # dictionary to hold flows


# Step 1: Extract all packets that belong to the same flow
# tuple consisting of: [srcIP addr, srcport, destIP addr, destport, tranproto]
find_flows()
# Step 2: Extract the interested value from each packet of the flow
# and calculate a statistical measure (max, min, avg, std_dev...)
# Things to include
# time, number of packets in flow, tcp(1)/udp(0), average packet length
extract_data()
