#! /usr/bin/env python3

from scapy.all import *
from sys import *
import socket 
import os
import numpy as np
from collections import OrderedDict
import csv


# ******************************************************
# Function to find flows and place them in a dictionary
# ******************************************************
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

# ***********************************
# Function to remove noise from data
# ***********************************
def remove_flows():

    # list of keys to be deleted
    selectedkeys = []

    for key in flows.keys():
        # finds number of packets in each flow
        flow_size = len(flows[key])
        # if there's less that 10 flows delete
        if flow_size > 10:
            selectedkeys.append(key)

    # delete selected keys from list of flows
    for key in selectedkeys:
        if key in flows.keys():
            del flows[key]

# *********************************************
# Function to return the port # for a service
# *********************************************
def find_port_number(port):
    if port == 'https':
        return 443
    elif port == 'domain':
        return 53
    elif port == 'http':
        return 80
    elif port == 'mdns':
        return 5353
    elif port == 'n2nremote':
        return 1683
    elif port == 'tivoconnect':
        return 2190
    elif port == 'cleanerliverc':
        return 3481
    elif port == 'plethora':
        return 3480
    elif port == 'ssdp':
        return 1900
    else:
        if type(port) == int:
            return port
        else:
            try:
                return int(port)
            except ValueError:
                print(f'cant find {port}')
                return 0

# *********************************************
# Function to extract data from flows into csv
# *********************************************
def extract_data():
    csv_file = 'data.csv'
    with open(csv_file, 'a') as p:
        # write csv headers
        #p.write(str('flow_id, IPsrc, IPdst, proto, time, num packets, sport, dport, avg_packet_size, label\n'))

        flow_id = 0

        # for each flow
        for key in flows.keys():
            # finds number of packets in each flow
            flow_size = len(flows[key])

            # find protocol and ports for each flow
            temp_proto = flows[key][0].sprintf('%IP.proto%')
            if temp_proto == 'tcp':
                protocol = 1

                flow_sport = find_port_number(flows[key][0].sprintf('%TCP.sport%'))
                flow_dport = find_port_number(flows[key][0].sprintf('%TCP.dport%'))

            elif temp_proto == 'udp':
                protocol = 0

                flow_sport = find_port_number(flows[key][0].sprintf('%UDP.sport%'))
                flow_dport = find_port_number(flows[key][0].sprintf('%UDP.dport%'))

            # find avg packet size
            total_packet_size = 0
            for packet in flows[key]:
                total_packet_size += int(packet.sprintf('%IP.len%'))
            avg_packet_size = total_packet_size/flow_size

            # gather values to go into csv
            # *** a lot of this can be removed, just messing around for now ***
            tempflow_id = flow_id
            tempIPsrc = flows[key][0].sprintf('%IP.src%')
            tempIPdst = flows[key][0].sprintf('%IP.dst%')
            tempproto = protocol
            temptime = flows[key][0].time
            tempnum_packets = total_packet_size
            tempsport = flow_sport
            tempdport = flow_dport
            tempavg_packet_size = avg_packet_size
            templabel = label

            # output flow data to csv file
            #csv_row = '%d, %d, %d, %d, %d, %d, %d, %d, %d, %d\n' % (tempflow_id, tempIPsrc, tempIPdst, tempproto,
            #                                                        temptime, tempnum_packets, tempsport, tempdport,
            #                                                        tempavg_packet_size, templabel)

            csv_row = f'{tempflow_id}, {tempIPsrc}, {tempIPdst}, {tempproto}, ' \
                      f'{temptime}, {tempnum_packets}, {tempsport}, {tempdport}, {tempavg_packet_size}, {templabel}\n'

            p.write(csv_row)

            # increment counter id
            flow_id += 1

# *********************************
# Start Program!
# ********************************
c = 20000  # variable for amount of packets to collect
flows = {}  # dictionary to hold flows
label = input("What activity are you preforming:\n [1] Web browsing\n "
              "[2] Video Streaming (e.g. Youtube)\n [3] Video Conference (e.g. Skype)\n [4] File Download\n")

packets = sniff(count=c)

# Step 1: Extract all packets that belong to the same flow
# tuple consisting of: [srcIP addr, srcport, destIP addr, destport, tranproto]
find_flows()

remove_flows() # remove noise

# Step 2: Extract the interested value from each packet of the flow
# and calculate a statistical measure (max, min, avg, std_dev...)
extract_data()
