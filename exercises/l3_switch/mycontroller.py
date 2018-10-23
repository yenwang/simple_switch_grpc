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

def writeARPReply(p4info_helper, sw, src_mac, dst_mac, port=None):
    table_entry = p4info_helper.buildTableEntry(
    table_name = "MyIngress.arp_exact",
    match_fields = {
	"hdr.ethernet.srcAddr": src_mac,
	"hdr.ethernet.dstAddr": dst_mac
    },
    action_name = "MyIngress.arp_reply",
    action_params = {
	"port" : port
    })
    sw.WriteTableEntry(table_entry)

def writeARPFlood(p4info_helper, sw, src_mac, dst_mac, port=None):
    table_entry = p4info_helper.buildTableEntry(
    table_name = "MyIngress.arp_exact",
    match_fields = {
	"hdr.ethernet.srcAddr": src_mac,
	"hdr.ethernet.dstAddr": dst_mac
    },
    action_name = "MyIngress.flooding"
    )
    sw.WriteTableEntry(table_entry)

def writeIPRules(p4info_helper, sw, dst_ip, mask, port):
    table_entry = p4info_helper.buildTableEntry(
    table_name = "MyIngress.ipv4_lpm",
    match_fields = {
	"hdr.ipv4.dstAddr": (dst_ip, mask)
    },
    action_name = "MyIngress.lan_forward",
    action_params={
	"port":port
    })
    sw.WriteTableEntry(table_entry)

def writeCPURules(p4info_helper, sw, dst_ip, mask):
    table_entry = p4info_helper.buildTableEntry(
    table_name = "MyIngress.ipv4_lpm",
    match_fields = {
	"hdr.ipv4.dstAddr": (dst_ip, mask)
    },
    action_name = "MyIngress.send_to_cpu"
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
    #arp_table = {}
    port_map = {}
    ip_rules = []
    #arp_rules = {}
    arp_rules = []
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
	    #sleep(2)
            content = s1.ReadPacketIn()
	    if content.WhichOneof('update')=='packet':
                packet = content.packet.payload
                #hex_packet = binascii.hexlify(content.packet.payload)
	        pkt = Ether(_pkt=packet)
		#pkt.hide_defaults()
		#pkt.show()
		metadata = content.packet.metadata
		for meta in metadata:
                    metadata_id = meta.metadata_id
                    value = meta.value
		    #print "Metadata_id = %d, value = %d%d\n" %(metadata_id, ord(value[0]), ord(value[1]))
		#print "Raw packet data: %s\n" % hex_packet
		
                pkt_eth_src = pkt.getlayer(Ether).src
                pkt_eth_dst = pkt.getlayer(Ether).dst
		ether_type = pkt.getlayer(Ether).type
		print "Received Packet-in type=%d\n" % ether_type
		if ether_type == 2054:#arp
		    print "Received a arp packet"
		    #pkt_ip_src = pkt.getlayer(ARP).psrc
		    #pkt_ip_dst = pkt.getlayer(ARP).pdst
		    #arp_table.setdefault(pkt_ip_src, pkt_eth_src)
		    #port_map.setdefault(pkt_ip_src, value)#not sure should use ord[value[1]] or value
		    port_map.setdefault(pkt_eth_src, value)
		    #arp_rules.setdefault(pkt_eth_src, [])
		    #if pkt_eth_dst != bcast:
		        #arp_rules.setdefault(pkt_eth_dst, [])
		    if pkt_eth_dst == bcast:
			#if bcast not in arp_rules[pkt_eth_src]:
			if bcast not in arp_rules:
			    #writeARPFlood(p4info_helper, sw=s1, src_mac=pkt_eth_src, dst_mac=bcast)
			    #arp_rules[pkt_eth_src].append(bcast)
			    writeARPFlood(p4info_helper, sw=s1, dst_mac=bcast)
			    arp_rules.append(bcast)
		    else:
			if pkt_eth_dst not in arp_rules:
			    writeARPReply(p4info_helper, sw=s1, dst_mac=pkt_eth_dst, port=port_map[pkt_eth_dst])
			    arp_rules.append(pkt_eth_dst)
			if pkt_eth_src not in arp_rules:
			    writeARPReply(p4info_helper, sw=s1, dst_mac=pkt_eth_src, port=port_map[pkt_eth_src])
			    arp_rules.append(pkt_eth_src)
		    '''
		    if pkt_ip_dst in arp_table:
			#packetout #send packet-in packet to where it's destined
			if pkt_eth_dst not in arp_rules[pkt_eth_src]:
			    writeARPReply(p4info_helper, sw=s1, src_mac=pkt_eth_src, dst_mac=pkt_eth_dst, port=port_map[pkt_ip_dst])
			    arp_rules[pkt_eth_src].append(pkt_eth_dst)
			if pkt_eth_src not in arp_rules[pkt_eth_dst]:
			    writeARPReply(p4info_helper, sw=s1, src_mac=pkt_eth_dst, dst_mac=pkt_eth_src, port=port_map[pkt_ip_src])
			    arp_rules[pkt_eth_dst].append(pkt_eth_src)
		    else:
			#packetout #send packet-in packet to where it's destined
			    if "ff:ff:ff:ff:ff:ff" not in arp_rules[pkt_eth_src]:
			        writeARPFlood(p4info_helper, sw=s1, src_mac=pkt_eth_src, dst_mac="ff:ff:ff:ff:ff:ff")
				arp_rules[pkt_eth_src].append("ff:ff:ff:ff:ff:ff")
		    '''
		elif ether_type == 2048:#ip
		    print "Received a ipv4 packet"
		    #send packet-in packet to where it's destined
		    pkt_ip_src = pkt.getlayer(IP).src
		    pkt_ip_dst = pkt.getlayer(IP).dst
		    if pkt_ip_dst in port_map:
			if pkt_ip_dst not in ip_rules:
			    writeIPRules(p4info_helper, sw=s1, dst_ip=pkt_ip_dst, mask=32, port=port_map[pkt_ip_dst])
			    ip_rules.append(pkt_ip_dst)
			if pkt_ip_src not in ip_rules:
			    writeIPRules(p4info_helper, sw=s1, dst_ip=pkt_ip_src, mask=32, port=port_map[pkt_ip_src])
			    ip_rules.append(pkt_ip_src)
		print "arp_table:%s\n" % arp_table
		print "port_map:%s\n" % port_map
		print "arp_rules:%s\n" % arp_rules
		print "ip_rules:%s\n" % ip_rules
		
            
            

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
