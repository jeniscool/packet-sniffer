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
# Used for reliable connections•
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
# Function to pull data from packets
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
# Function to find flows
# **********************************
def find_flows():
    # for all packets found, group them into flows
    for packet in packets:
        # a flow is a tuple consisting of: [srcIP addr, srcport, destIP addr, destport, tranproto]
        # assign to each flow an ID, which is shared among all packets of that flow.
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

    # ****** DELETE LATER ******
    print(f'Number of flows: {len(flows)}')

# **********************************
# Function to fill csv with packet data
# **********************************
# def fill_csv():
#    with open('packet-data.csv', mode='w') as csvfile:
        # print("hi")
        # pd-writer = csv.writer(pd, deliminator = ',', quotechar = '"')
#        fieldNames = ['flow_id', 'feature_1', 'feature_2', 'feature_3', 'feature_4', 'label']


# *********************************
# Main function!
# *********************************
def main():
    # Step 1: Extract all packets that belong to the same flow
    # tuple consisting of: [srcIP addr, srcport, destIP addr, destport, tranproto]
    find_flows()

    # Step 2: Extract the interested value from each packet of the flow
    # and calculate a statistical measure (max, min, avg, std_dev...)



# *********************************
# Global Variables
# ********************************
cPackets = Counter() # packet counter
c = 50 # variable for amount of packets to collect
# packets = sniff(prn=fields_extraction, count=c) # sniffed packets
packets = sniff(count = c)
# might need numpy arrays to hold features in classes
flows = {}  # dictionary to hold flows

# *****************
# Begin Program!
# *****************
main()