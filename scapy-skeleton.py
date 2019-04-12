#! /usr/bin/env python3

from scapy.all import *
from sys import *
import socket 
import os
import numpy as np
from collections import Counter
import csv


# **********************************
# Function to find flows and place them in a dictionary
# **********************************
def find_flows():
    for packet in packets:
        # collect flow info for packet
        ip_src = packet.sprintf('%IP.src%')
        ip_dst = packet.sprintf('%IP.dst%')
        ip_proto = packet.sprintf('%IP.proto%')
        # check packet protocol
        if ip_proto == 'tcp':
            sport = packet.sprintf('%TCP.sport%')
            dport = packet.sprintf('%TCP.dport%')
        elif ip_proto == 'udp':
            sport = packet.sprintf('%UDP.sport%')
            dport = packet.sprintf('%UDP.dport%')
        else:
            continue

        # create id for this packet's flow
        flow_id = (ip_src, ip_dst, ip_proto, sport, dport)

        # add flow to dictionary of flows
        if flow_id in flows:
            flows[flow_id].append(packet)
        else:  # else check for bi-directional flows
            bi_id = (ip_dst, ip_src, ip_proto, dport, sport)
            if bi_id in flows:
                flows[bi_id].append(packet)
            else:  # if not, create a new flow in dictionary
                flows[flow_id] = [packet]


# *********************************
# Function to extract data from flows into csv
# *********************************
def extract_data():
    csv_file = 'test.csv'
    with open(csv_file, 'w') as p:
        # write csv headers
        p.write(str('num packets, proto, sport, dport, avg packet size\n'))

        # for each flow
        for key in flows.keys():
            # finds number of packets in each flow
            flow_size = len(flows[key])

            # find protocol and ports for each flow
            temp_proto = flows[key][0].sprintf('%IP.proto%')
            if temp_proto == 'tcp':
                protocol = 1
                if flows[key][0].sprintf('%TCP.sport%') == 'https':
                    flow_sport = 443
                elif flows[key][0].sprintf('%TCP.sport%') == 'domain':
                    flow_sport = 53
                elif flows[key][0].sprintf('%TCP.sport%') == 'http':
                    flow_sport = 80
                elif flows[key][0].sprintf('%TCP.sport%') == 'mdns':
                    flow_sport = 5353
                else:
                    flow_sport = int(flows[key][0].sprintf('%TCP.sport%'))
                if flows[key][0].sprintf('%TCP.dport%') == 'https':
                    flow_dport = 443
                elif flows[key][0].sprintf('%TCP.dport%') == 'domain':
                    flow_dport = 53
                elif flows[key][0].sprintf('%TCP.dport%') == 'http':
                    flow_dport = 80
                elif flows[key][0].sprintf('%TCP.dport%') == 'mdns':
                    flow_dport = 5353
                else:
                    flow_dport = int(flows[key][0].sprintf('%TCP.dport%'))
            elif temp_proto == 'udp':
                protocol = 0
                if flows[key][0].sprintf('%UDP.sport%') == 'https':
                    flow_sport = 443
                elif flows[key][0].sprintf('%UDP.sport%') == 'domain':
                    flow_sport = 53
                elif flows[key][0].sprintf('%UDP.sport%') == 'http':
                    flow_sport = 80
                elif flows[key][0].sprintf('%UDP.sport%') == 'mdns':
                    flow_sport = 5353
                else:
                    flow_sport = int(flows[key][0].sprintf('%UDP.sport%'))
                if flows[key][0].sprintf('%UDP.dport%') == 'https':
                    flow_dport = 443
                elif flows[key][0].sprintf('%UDP.dport%') == 'domain':
                    flow_dport = 53
                elif flows[key][0].sprintf('%UDP.dport%') == 'http':
                    flow_dport = 80
                elif flows[key][0].sprintf('%UDP.dport%') == 'mdns':
                    flow_dport = 5353
                else:
                    flow_dport = int(flows[key][0].sprintf('%UDP.dport%'))

            # find avg packet size
            total_packet_size = 0
            for packet in flows[key]:
                total_packet_size += int(packet.sprintf('%IP.len%'))
            avg_packet_size = total_packet_size/flow_size

            # output flow data to csv file
            csv_row = '%d, %d, %d, %d, %d\n' % (flow_size, protocol, flow_sport, flow_dport, avg_packet_size)
            p.write(csv_row)


# *********************************
# Start Program!
# ********************************
c = 1000  # variable for amount of packets to collect
flows = {}  # dictionary to hold flows

packets = sniff(count=c)

# Step 1: Extract all packets that belong to the same flow
# tuple consisting of: [srcIP addr, srcport, destIP addr, destport, tranproto]
find_flows()

# Step 2: Extract the interested value from each packet of the flow
# and calculate a statistical measure (max, min, avg, std_dev...)
extract_data()
