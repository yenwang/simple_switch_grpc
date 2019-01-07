#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def writeIPRules(p4info_helper, sw, dst_ip, mask, nhop_ip):
    table_entry = p4info_helper.buildTableEntry(
    table_name = "MyIngress.ipv4_lpm",
    match_fields = {
	"hdr.ipv4.dstAddr": (dst_ip, mask)
    },
    action_name = "MyIngress.set_nhop",
    action_params={
	"nhop": (nhop_ip)
    })
    sw.WriteTableEntry(table_entry)

def writeNhopRules(p4info_helper, sw, nhop_ip, port, dmac):
    table_entry = p4info_helper.buildTableEntry(
    table_name = "MyIngress.nhop_exact",
    match_fields = {
	"meta.nhop_ip": (nhop_ip)
    },
    action_name = "MyIngress.forward",
    action_params={
	"port": port,
	"dmac": dmac
    })
    sw.WriteTableEntry(table_entry)

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s4',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s4-p4runtime-requests.txt')

        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s4.MasterArbitrationUpdate()

        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s3"
        s4.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s4"

	register_entry = p4info_helper.buildRegisterEntry(
	    register_name = "ingress_register",
	    index = 0,
	    data = "\000"
	)
	s1.WriteRegisterEntry(register_entry)
	print "Write device_id to register on s1"

	#############################################################################
	writeIPRules(p4info_helper, sw=s1, dst_ip="10.0.1.1", mask=32, nhop_ip="10.0.1.1")
	writeIPRules(p4info_helper, sw=s1, dst_ip="10.0.1.2", mask=32, nhop_ip="10.0.1.2")
	writeIPRules(p4info_helper, sw=s1, dst_ip="10.0.4.0", mask=24, nhop_ip="140.116.82.2")
	writeNhopRules(p4info_helper, sw=s1, nhop_ip="140.116.82.2", port=3, dmac="00:00:02:02:02:02")
	writeNhopRules(p4info_helper, sw=s1, nhop_ip="10.0.1.1", port=1, dmac="00:00:00:00:01:01")
	writeNhopRules(p4info_helper, sw=s1, nhop_ip="10.0.1.2", port=2, dmac="00:00:00:00:01:02")

	writeIPRules(p4info_helper, sw=s2, dst_ip="10.0.1.0", mask=24, nhop_ip="140.116.82.1")
	writeIPRules(p4info_helper, sw=s2, dst_ip="10.0.4.0", mask=24, nhop_ip="140.116.82.3")
	writeNhopRules(p4info_helper, sw=s2, nhop_ip="140.116.82.1", port=1, dmac="00:00:01:01:01:01")
	writeNhopRules(p4info_helper, sw=s2, nhop_ip="140.116.82.3", port=2, dmac="00:00:03:03:03:03")

	writeIPRules(p4info_helper, sw=s3, dst_ip="10.0.1.0", mask=24, nhop_ip="140.116.82.2")
	writeIPRules(p4info_helper, sw=s3, dst_ip="10.0.4.0", mask=24, nhop_ip="140.116.82.4")
	writeNhopRules(p4info_helper, sw=s3, nhop_ip="140.116.82.2", port=1, dmac="00:00:02:02:02:02")
	writeNhopRules(p4info_helper, sw=s3, nhop_ip="140.116.82.4", port=2, dmac="00:00:04:04:04:04")

	writeIPRules(p4info_helper, sw=s4, dst_ip="10.0.4.3", mask=32, nhop_ip="10.0.4.3")
	writeIPRules(p4info_helper, sw=s4, dst_ip="10.0.4.4", mask=32, nhop_ip="10.0.4.4")
	writeIPRules(p4info_helper, sw=s4, dst_ip="10.0.1.0", mask=24, nhop_ip="140.116.82.3")
	writeNhopRules(p4info_helper, sw=s4, nhop_ip="140.116.82.3", port=3, dmac="00:00:03:03:03:03")
	writeNhopRules(p4info_helper, sw=s4, nhop_ip="10.0.4.3", port=1, dmac="00:00:00:00:04:03")
	writeNhopRules(p4info_helper, sw=s4, nhop_ip="10.0.4.4", port=2, dmac="00:00:00:00:04:04")
	#############################################################################

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/register.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/register.json')
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
