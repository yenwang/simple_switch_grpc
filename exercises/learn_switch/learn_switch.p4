#include <core.p4>
#include <v1model.p4>

const bit<9> CPU_PORT = 255;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<16> mcast_group_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<16> mcast;
}

struct metadata {
    
}

struct headers {
    ethernet_t ethernet;
    packet_in_header_t packet_in;
    packet_out_header_t packet_out;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port){
	    CPU_PORT: parse_packet_out;
	    default: parse_ethernet;
	}
    }

    state parse_packet_out{
	packet.extract(hdr.packet_out);
	transition parse_ethernet;
    }

    state parse_ethernet {
	packet.extract(hdr.ethernet);
	transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action send_to_cpu(){
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }
    
    action flooding(){
	standard_metadata.mcast_grp = 1;
    }

    action arp_reply(egressSpec_t port){
	standard_metadata.egress_spec = port;
    }

    table arp_exact{
	key = {
	    standard_metadata.ingress_port: exact;
	    hdr.ethernet.dstAddr: exact;
	}
	actions = {
	    send_to_cpu;
	    flooding;
	    arp_reply;
	}
	size = 1024;
	default_action = send_to_cpu();
    }

    table debug_table{
	key = {
	    hdr.packet_out.egress_port: exact;
	}
	actions = {NoAction;}
	size = 1024;
	default_action = NoAction;
    }

    apply {
	    if(standard_metadata.ingress_port == CPU_PORT){
		debug_table.apply();
		standard_metadata.egress_spec = hdr.packet_out.egress_port;
		standard_metadata.mcast_grp = hdr.packet_out.mcast;
		hdr.packet_out.setInvalid();
	    }
	    else{
		arp_exact.apply();
	    }
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in);
	packet.emit(hdr.ethernet);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
