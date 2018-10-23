#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep
from scapy.all import *
import binascii

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def writeARPReply(p4info_helper, sw, in_port, dst_mac, port=None):
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

def writeARPFlood(p4info_helper, sw, in_port, dst_mac, port=None):
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

def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    port_map = {}
    arp_rules = {}
    flag = 0
    bcast = "ff:ff:ff:ff:ff:ff"
    try:
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        content = s1.MasterArbitrationUpdate()
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
	while True:
            content = s1.ReadPacketIn()
	    if content.WhichOneof('update')=='packet':
                packet = content.packet.payload
                #hex_packet = binascii.hexlify(content.packet.payload)
	        pkt = Ether(_pkt=packet)
		metadata = content.packet.metadata
		for meta in metadata:
                    metadata_id = meta.metadata_id
                    value = meta.value
		    #print "Metadata_id = %d, value = %d%d\n" %(metadata_id, ord(value[0]), ord(value[1]))
		#print "Raw packet data: %s\n" % hex_packet
		
                pkt_eth_src = pkt.getlayer(Ether).src
                pkt_eth_dst = pkt.getlayer(Ether).dst
		ether_type = pkt.getlayer(Ether).type

		if ether_type == 2048 or ether_type == 2054:#learn_switch is only capable of dealing with ip or arp packets
		    port_map.setdefault(pkt_eth_src, value)
		    arp_rules.setdefault(value, [])

		    #pkt.hide_defaults()
		    #pkt.show()
		    if pkt_eth_dst == bcast:
		        if bcast not in arp_rules:
			    writeARPFlood(p4info_helper, sw=s1, in_port=value, dst_mac=bcast)
			    arp_rules[value].append(bcast)
			#packet out original packet
			packet_out = p4info_helper.buildPacketOut(
			    payload = packet,
			    metadata = {
				1 : "\000\000",
				2 : "\000\001"
			    }
			)
			s1.WritePacketOut(packet_out)
		    else:
		        if pkt_eth_dst not in arp_rules[value]:
			    writeARPReply(p4info_helper, sw=s1, in_port=value, dst_mac=pkt_eth_dst, port=port_map[pkt_eth_dst])
			    arp_rules[value].append(pkt_eth_dst)
		        if pkt_eth_src not in arp_rules[port_map[pkt_eth_dst]]:
			    writeARPReply(p4info_helper, sw=s1, in_port=port_map[pkt_eth_dst], dst_mac=pkt_eth_src, port=port_map[pkt_eth_src])
			    arp_rules[port_map[pkt_eth_dst]].append(pkt_eth_src)
			#packet out original packet
			packet_out = p4info_helper.buildPacketOut(
			    payload = packet,
			    metadata = {
				1: port_map[pkt_eth_dst],
				2: "\000\000"
			    }
			)
			s1.WritePacketOut(packet_out)

		    print "port_map:%s\n" % port_map
		    print "arp_rules:%s\n" % arp_rules
		
            
            

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/learn_switch.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/learn_switch.json')
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
