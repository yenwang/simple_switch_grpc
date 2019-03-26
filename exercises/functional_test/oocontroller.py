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
from p4runtime_lib.convert import *
import threading
import netaddr

SWITCH_NUM = 2

class Controller(object):

    def __init__(self, p4info_file_path, bmv2_file_path, switch_num):
	self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
	self.bmv2_file_path = bmv2_file_path
	self.switch_list = []
	self.num = switch_num
	self.lookup_table = {}
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

    def writeIPRules(self, num, dst_ip, dstAddr, port):
	table_entry = self.p4info_helper.buildTableEntry(
	    table_name = "MyIngress.ipv4_lpm",
	    match_fields = {
		"hdr.ipv4.dstAddr": dst_ip
	    },
	    action_name = "MyIngress.ipv4_forward",
	    action_params = {
		"dstAddr": dstAddr,
		"port": port
	    }
	)
	self.switch_list[num].WriteTableEntry(table_entry)

    def setLookupTable(self):
	for num in range(1, self.num + 1):
	    if num == 1:
		self.lookup_table.setdefault((1,"10.0.2.2"), ("00:00:02:02:02:02", 2))
		self.lookup_table.setdefault((1,"10.0.1.1"), ("00:00:00:00:01:01", 1))
	    else:	
		self.lookup_table.setdefault((2,"10.0.2.2"), ("00:00:00:00:02:02", 1))
		self.lookup_table.setdefault((2,"10.0.1.1"), ("00:00:01:01:01:01", 2))
	print self.lookup_table

    def setMaster(self):
	for sw in self.switch_list:
	    sw.MasterArbitrationUpdate()
	    print "Controller is now master of switch\n"
    
    def setPipeline(self):
	for sw in self.switch_list:
	    sw.SetForwardingPipelineConfig(p4info = self.p4info_helper.p4info,
				bmv2_json_file_path = self.bmv2_file_path)
	    print "Installed P4 program using SetForwardingPipelineConfig on switch\n", 

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
	    print "Installed multicast group on switch\n"

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
	    #keep listening to event sent from switch
	    po_flag = False
            content = sw.ReadPacketIn()

	    if content.WhichOneof('update')=='digest':#process digest
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

	    elif content.WhichOneof('update')=='packet':#process packet-in
		print "receive packet-in by thread ", num + 1
		packet = content.packet.payload
		pkt = Ether(_pkt=packet)
		metadata = content.packet.metadata
		meta_val = []
		for meta in metadata:
		    meta_val.append(meta.value)
		pkt_ip_dst = pkt.getlayer(IP).dst
		pkt_ip_src = pkt.getlayer(IP).src
		pkt_eth_dst = pkt.getlayer(Ether).dst
		#int_pkt_ip_dst = int(netaddr.IPAddress(pkt_ip_dst))
		#masked_pkt_ip_dst = int_pkt_ip_dst >> (32-self.mask)
		if (num+1, pkt_ip_dst) in self.lookup_table:
		    (dstAddr1, port1) = self.lookup_table[(num+1, pkt_ip_dst)]
		    self.writeIPRules(num=num, dst_ip=pkt_ip_dst, dstAddr=dstAddr1, port=port1)
		    po_flag = True
		    print "Successfully installed rules: match ip=%s, action params = %s %d" % (pkt_ip_dst, dstAddr1, port1)

		if (num+1, pkt_ip_src) in self.lookup_table: #duo way
		    (dstAddr2, port2) = self.lookup_table[(num+1, pkt_ip_src)]
		    self.writeIPRules(num=num, dst_ip=pkt_ip_src, dstAddr=dstAddr2, port=port2)
		    print "Successfully installed rules: match ip=%s, action params = %s %d" % (pkt_ip_src, dstAddr2, port2)

		''' #proactive way
		if (num+2, pkt_ip_dst) in self.lookup_table:
		    (dstAddr2, port2) = self.lookup_table[(num+2, pkt_ip_dst)]
		    self.writeIPRules(num=num+1, dst_ip=pkt_ip_dst, dstAddr=dstAddr2, port=port2)
		    print "Successfully installed rules: match ip=%s, action params = %s %d" % (pkt_ip_dst, dstAddr2, port2)

		if (num, pkt_ip_dst) in self.lookup_table:
		    (dstAddr3, port3) = self.lookup_table[(num, pkt_ip_dst)]
		    self.writeIPRules(num=num-1, dst_ip=pkt_ip_dst, dstAddr=dstAddr3, port=port3)
		    print "Successfully installed rules: match ip=%s, action params = %s %d" % (pkt_ip_dst, dstAddr3, port3)
		'''

		if po_flag:
		    packet_out = self.p4info_helper.buildPacketOut(
			payload = packet,
			metadata = {
			    "egress_port": port1,
			    "srcAddr": pkt_eth_dst,
			    "dstAddr": dstAddr1
			}
		    )
		    sw.WritePacketOut(packet_out)
		    print "Successfully packet-out", num + 1

    def allocateThread(self):
	threads = []
	for num in range(self.num):
	   threads.append(threading.Thread(target = self.processNotify, args = (num,)))
	   threads[num].start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/functional_test.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/functional_test.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)

    my_controller = Controller(args.p4info, args.bmv2_json, SWITCH_NUM)
    my_controller.setLookupTable()
    my_controller.setMaster()
    my_controller.setPipeline()
    my_controller.setPRE()
    #my_controller.setDigest()
    my_controller.allocateThread()	
