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

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2


def writeTableRules(p4info_helper, sw, dst_ip_addr, mask, port):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, mask)
        },
        action_name="MyIngress.lan_forward",
        action_params={
            "port": port,
        })
    sw.WriteTableEntry(table_entry)
    print "Installed  rule on %s: ip_dst = %s/%d outport= %d" % (sw, dst_ip_addr, mask, port)



def readTableRules(p4info_helper, sw):

    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print
############################################################################################
def printDirectCounter(p4info_helper, sw, table_name=None):
    if table_name is not None:
        for response in sw.ReadDirectCounters(table_id = p4info_helper.get_tables_id(table_name)):
	    for entity in response.entities:
	        direct_counter = entity.direct_counter_entry
	        #table_id
	        print "direct counter of %s: %d packets (%d bytes)" % (table_name, direct_counter.data.packet_count, direct_counter.data.byte_count)
    else:
        for response in sw.ReadDirectCounters():
	    for entity in response.entities:
	        direct_counter = entity.direct_counter_entry
	        #table_id
	        print "direct counter of %s: %d packets (%d bytes)" % (p4info_helper.get_tables_name(direct_counter.table_entry.table_id), direct_counter.data.packet_count, direct_counter.data.byte_count)
############################################################################################
def printCounter(p4info_helper, sw, counter_name=None, index=None):

    if counter_name is None:
        for response in sw.ReadCounters():
            for entity in response.entities:
                counter = entity.counter_entry
                print "%s %s %s: %d packets (%d bytes)" % (
                    sw.name, p4info_helper.get_counters_name(counter.counter_id), counter.index,
                    counter.data.packet_count, counter.data.byte_count
            )
    else:
        for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry
                print "%s %s %d: %d packets (%d bytes)" % (
                    sw.name, counter_name, index,
                    counter.data.packet_count, counter.data.byte_count
                )

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
        s1.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"

        # Write table entries
        writeTableRules(p4info_helper, sw=s1, dst_ip_addr="10.0.1.1", mask=32, port=1)
        writeTableRules(p4info_helper, sw=s1, dst_ip_addr="10.0.1.2", mask=32, port=2)
        writeTableRules(p4info_helper, sw=s1, dst_ip_addr="10.0.1.3", mask=32, port=3)
        writeTableRules(p4info_helper, sw=s1, dst_ip_addr="10.0.1.4", mask=32, port=4)

        readTableRules(p4info_helper, s1)

        # Print the tunnel counters every 2 seconds
	'''
        while True:
            sleep(2)
            print '\n----- Reading tunnel counters -----'
            printCounter(p4info_helper, s1, "MyIngress.ingressTunnelCounter", 100)
            printCounter(p4info_helper, s2, "MyIngress.egressTunnelCounter", 100)
            printCounter(p4info_helper, s2, "MyIngress.ingressTunnelCounter", 200)
            printCounter(p4info_helper, s1, "MyIngress.egressTunnelCounter", 200)
	'''
        while True:
            sleep(2)
            print '\n----- Reading direct counters -----'
            printDirectCounter(p4info_helper, s1, table_name="MyIngress.ipv4_lpm")	
    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/direct_counter.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/direct_counter.json')
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
