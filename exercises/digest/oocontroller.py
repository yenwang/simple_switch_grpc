#!/usr/bin/env python2

import argparse
import grpc
import os
import sys
from time import sleep
from scapy.all import *
import binascii
import numpy as np
import time
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper
import threading

class Controller(object):

    def __init__(self, p4info_file_path, bmv2_file_path, switch_num):
	self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
	self.bmv2_file_path = bmv2_file_path
	self.switch_list = []
	self.num = switch_num
	self.bcast = "ff:ff:ff:ff:ff:ff"
	self.port_map = {}
	self.arp_rules = {}

	for num in range(1, switch_num + 1):
	    sw_name = 's' + str(num)
	    port = 50051 + num - 1
	    dump_name = 'logs/' + sw_name + '-p4runtime-requests.txt'

	    sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            	name = sw_name,
            	address ='127.0.0.1:' + str(port),
            	device_id = num - 1,
            	proto_dump_file = dump_name)

	    self.switch_list.append(sw)

    def writeARPReply(self, num, in_port, dst_mac, port=None):    #write rules to arp_exact table with action arp_reply
        table_entry = self.p4info_helper.buildTableEntry(
        table_name = "MyIngress.arp_exact",
        match_fields = {
	    "standard_metadata.ingress_port" : in_port,
	    "hdr.ethernet.dstAddr": dst_mac
        },
        action_name = "MyIngress.arp_reply",
        action_params = {
	    "port" : port
        })
        self.switch_list[num].WriteTableEntry(table_entry)

    def writeARPFlood(self, num, in_port, dst_mac, port=None):    #write rules to arp_exact table with action flooding
        table_entry = self.p4info_helper.buildTableEntry(
        table_name = "MyIngress.arp_exact",
        match_fields = {
	    "standard_metadata.ingress_port" : in_port,
	    "hdr.ethernet.dstAddr": dst_mac
        },
        action_name = "MyIngress.flooding"
        )
        self.switch_list[num].WriteTableEntry(table_entry)

    def setMaster(self):
	for sw in self.switch_list:
	    sw.MasterArbitrationUpdate()
	    print "Controller is now master of switch"
    
    def setPipeline(self):
	for sw in self.switch_list:
	    sw.SetForwardingPipelineConfig(p4info = self.p4info_helper.p4info,
				bmv2_json_file_path = self.bmv2_file_path)
	    print "Installed P4 program using SetForwardingPipelineConfig on switch", 

    def setPRE(self):
        mc_group_entry = self.p4info_helper.buildMCEntry(
            mc_group_id = 1,
            replicas={
                1 : 1,
                2 : 2,
                3 : 3,
                4 : 4
            }
        )

	for sw in self.switch_list:
	    sw.WritePRE(mc_group = mc_group_entry)
	    print "Installed multicast group on switch"

    def setDigest(self):
        digest_entry = self.p4info_helper.buildDigestEntry(
            digest_name = "mac_learn_digest_t",
            max_timeout_ns = 0,
            max_list_size = 1,
            ack_timeout_ns = 0
        )

	for sw in self.switch_list:
            sw.WriteDigestEntry(digest_entry)
	    print "Installed digest entry on switch"

    def prettify(self, mac_string):
	return ':'.join('%02x' % ord(b) for b in mac_string)

    def processNotify(self, num):
	sw = self.switch_list[num]
	while True:
	    #keep listening to digest event sent from switch
	    print "Thread ",num
            content = sw.ReadPacketIn()
	    if content.WhichOneof('update')=='digest':
		digest = content.digest
		digest_id = digest.digest_id #digest instance id
		list_id = digest.list_id # the number of digest message sent from switch
		timestamp = digest.timestamp
		digest_data = digest.data
		for members in digest_data:
		    if members.WhichOneof('data')=='struct':
                        if members.struct.members[0].WhichOneof('data') == 'bitstring':
                            pkt_eth_src = self.prettify(members.struct.members[0].bitstring)
                        if members.struct.members[1].WhichOneof('data') == 'bitstring':
                            pkt_eth_dst = self.prettify(members.struct.members[1].bitstring)
                        if members.struct.members[2].WhichOneof('data') == 'bitstring':
                            ether_type = int(members.struct.members[2].bitstring.encode('hex'),16)
                        if members.struct.members[3].WhichOneof('data') == 'bitstring':
                            port_id = members.struct.members[3].bitstring

		if ether_type == 2048 or ether_type == 2054:    #learn_switch is only capable of dealing with ip or arp packets
		    self.port_map.setdefault(pkt_eth_src, port_id)
		    self.arp_rules.setdefault(port_id, [])
		  
		    if pkt_eth_dst == self.bcast:                    #arp_request packet processing
		        if self.bcast not in self.arp_rules:              #controller need to record written rules to avoid grpc error
			    self.writeARPFlood(num=num, in_port=port_id, dst_mac=self.bcast)
			    self.arp_rules[port_id].append(self.bcast)

		    else:                                       #arp_reply/ipv4 packet processing
		        if pkt_eth_dst not in self.arp_rules[port_id]:
			    self.writeARPReply(num=num, in_port=port_id, dst_mac=pkt_eth_dst, port=self.port_map[pkt_eth_dst])
			    self.arp_rules[port_id].append(pkt_eth_dst)
		        if pkt_eth_src not in self.arp_rules[self.port_map[pkt_eth_dst]]:
			    self.writeARPReply(num=num, in_port=self.port_map[pkt_eth_dst], dst_mac=pkt_eth_src, port=self.port_map[pkt_eth_src])
			    self.arp_rules[self.port_map[pkt_eth_dst]].append(pkt_eth_src)

		    print "port_map:%s\n" % self.port_map
		    print "arp_rules:%s\n" % self.arp_rules
    def allocateThread(self):
	threads = []
	for num in range(self.num):
	   threads.append(threading.Thread(target = self.processNotify, args = (num,)))
	   threads[num].start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/digest.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/digest.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)

    switch_num = 1
    my_controller = Controller(args.p4info, args.bmv2_json, switch_num)
    my_controller.setMaster()
    my_controller.setPipeline()
    my_controller.setPRE()
    my_controller.setDigest()
    my_controller.allocateThread()	
