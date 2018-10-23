#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep
from scapy.all import *
import binascii

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

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
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        content = s1.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"

	#############################################################################
	writeIPRules(p4info_helper, sw=s1, dst_ip="10.0.1.1", mask=32, port=1)
	writeIPRules(p4info_helper, sw=s1, dst_ip="10.0.1.2", mask=32, port=2)
	writeCPURules(p4info_helper, sw=s1, dst_ip="10.0.1.3", mask=32)
	writeIPRules(p4info_helper, sw=s1, dst_ip="10.0.1.4", mask=32, port=4)
	#############################################################################
	while True:
	    sleep(2)
            content = s1.ReadPacketIn()
	    if(content.WhichOneof('update')=='packet'):
		print("Received Packet-in\n")
                packet = content.packet.payload
                #hex_packet = binascii.hexlify(content.packet.payload)
	        pkt = Ether(_pkt=packet)
		pkt.hide_defaults()
		pkt.show()
		metadata = content.packet.metadata
		for meta in metadata:
                    metadata_id = meta.metadata_id
                    value = meta.value
		    print "Metadata_id = %d, value = %d%d\n" %(metadata_id, ord(value[0]), ord(value[1]))
		#print "Raw packet data: %s\n" % hex_packet
                #pkt_eth_src = pkt.getlayer(Ether).src
                #pkt_eth_dst = pkt.getlayer(Ether).dst
                #pkt_ip_src = pkt.getlayer(IP).src
                #pkt_ip_dst = pkt.getlayer(IP).dst
	        #print pkt_eth_src
	        #print pkt_eth_dst
	        #print pkt_ip_src
	        #print pkt_ip_dst
            
            

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/packet_in.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/packet_in.json')
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
