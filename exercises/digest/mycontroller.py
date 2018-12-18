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

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def writeARPReply(p4info_helper, sw, in_port, dst_mac, port=None):    #write rules to arp_exact table with action arp_reply
    table_entry = p4info_helper.buildTableEntry(
    table_name = "MyIngress.arp_exact",
    match_fields = {
	"standard_metadata.ingress_port" : in_port,
	"hdr.ethernet.dstAddr": dst_mac
    },
    action_name = "MyIngress.arp_reply",
    action_params = {
	"port" : port
    })
    sw.WriteTableEntry(table_entry)

def writeARPFlood(p4info_helper, sw, in_port, dst_mac, port=None):    #write rules to arp_exact table with action flooding
    table_entry = p4info_helper.buildTableEntry(
    table_name = "MyIngress.arp_exact",
    match_fields = {
	"standard_metadata.ingress_port" : in_port,
	"hdr.ethernet.dstAddr": dst_mac
    },
    action_name = "MyIngress.flooding"
    )
    sw.WriteTableEntry(table_entry)

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def prettify(mac_string):
    return ':'.join('%02x' % ord(b) for b in mac_string)

def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    port_map = {}
    arp_rules = {}
    flag = 0
    bcast = "ff:ff:ff:ff:ff:ff"

    try:
	# connect to grpc server s1
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
	#send MasterArbitrationUpdate to switch
        s1.MasterArbitrationUpdate()

	#SetForwardingPipleine using learn_switch.p4
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"

        mc_group_entry = p4info_helper.buildMCEntry(
            mc_group_id = 1,
            replicas={
                1 : 1,
                2 : 2,
                3 : 3,
                4 : 4
            }
        )
        s1.WritePRE(mc_group=mc_group_entry)
        print "Installed Multicast group on s1"
	max_timeout_ns = np.dtype(np.int64)
	max_timeout_ns = 0
	ack_timeout_ns = np.dtype(np.int64)
	ack_timeout_ns = 0
	s1.WriteDigestEntry(385931647, max_timeout_ns, 1, ack_timeout_ns)
	print "Digest Entry Set on s1"
	'''for use cases that host already knows destination MAC
	port_map = {'00:00:00:00:01:01': '\x00\x01', '00:00:00:00:01:02': '\x00\x02', '00:00:00:00:01:03': '\x00\x03', '00:00:00:00:01:04': '\x00\x04'}
	arp_rules = {'\x00\x01':[], '\x00\x02':[], '\x00\x03':[], '\x00\x04':[]}
	'''
	accumulation = 0
	counter = 0
	while True:
	    #keep listening to digest event sent from switch
	    #s1.WriteDigestAck(0,1)
            content = s1.ReadPacketIn()
	    begin = time.time()

	    if content.WhichOneof('update')=='digest':
		digest = content.digest
		digest_id = digest.digest_id #digest instance id
		list_id = digest.list_id # the number of digest message sent from switch
		timestamp = digest.timestamp
		digest_data = digest.data
		for members in digest_data:
		    if members.WhichOneof('data')=='struct':
                        if members.struct.members[0].WhichOneof('data') == 'bitstring':
                            pkt_eth_src = prettify(members.struct.members[0].bitstring)
                        if members.struct.members[1].WhichOneof('data') == 'bitstring':
                            pkt_eth_dst = prettify(members.struct.members[1].bitstring)
                        if members.struct.members[2].WhichOneof('data') == 'bitstring':
                            ether_type = int(members.struct.members[2].bitstring.encode('hex'),16)
                        if members.struct.members[3].WhichOneof('data') == 'bitstring':
                            port_id = members.struct.members[3].bitstring

		if ether_type == 2048 or ether_type == 2054:    #learn_switch is only capable of dealing with ip or arp packets
		    port_map.setdefault(pkt_eth_src, port_id)
		    arp_rules.setdefault(port_id, [])
		  
		    if pkt_eth_dst == bcast:                    #arp_request packet processing
		        if bcast not in arp_rules:              #controller need to record written rules to avoid grpc error
			    writeARPFlood(p4info_helper, sw=s1, in_port=port_id, dst_mac=bcast)
			    arp_rules[port_id].append(bcast)

		    else:                                       #arp_reply/ipv4 packet processing
		        if pkt_eth_dst not in arp_rules[port_id]:
			    writeARPReply(p4info_helper, sw=s1, in_port=port_id, dst_mac=pkt_eth_dst, port=port_map[pkt_eth_dst])
			    arp_rules[port_id].append(pkt_eth_dst)
		        if pkt_eth_src not in arp_rules[port_map[pkt_eth_dst]]:
			    writeARPReply(p4info_helper, sw=s1, in_port=port_map[pkt_eth_dst], dst_mac=pkt_eth_src, port=port_map[pkt_eth_src])
			    arp_rules[port_map[pkt_eth_dst]].append(pkt_eth_src)

		    #print "port_map:%s\n" % port_map
		    #print "arp_rules:%s\n" % arp_rules
		    counter += 1
            	    end = time.time()
		    delta = end - begin
		    accumulation = accumulation + delta
		    avg = accumulation / counter
		    print "Time delta for processing a digest message: %.9f" % (delta)
		    print "avg time processing a digest message: %.9f\n" % (avg)
            

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

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
    main(args.p4info, args.bmv2_json)
