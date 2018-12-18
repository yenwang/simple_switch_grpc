#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<9> CPU_PORT = 255; // I specify 255 for cpu port while running simple_switch_grpc with command --cpu-port 255
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<16> mcast_group_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
/*
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header arp_t {
    bit<16>   htype;
    bit<16>   ptype;
    bit<8>    hlen;
    bit<8>    plen;
    bit<16>   opcode;
    macAddr_t srcMAC;
    ip4Addr_t srcIP;
    macAddr_t dstMAC;
    ip4Addr_t dstIP;
}
*/
@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;    //for switch to carry the original ingress port of packet-in packet
    bit<7> padding;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;	   //for controller to tell switches to forward the packet-out packet through this field
    bit<16> mcast;	   //for controller to specify a multicast group if needed
    bit<7> padding;
}

struct mac_learn_digest_t {
    macAddr_t srcAddr;
    macAddr_t dstAddr;
    bit<16>   etherType;
    bit<16>   ingress_port;
}

struct metadata {
    
}

struct headers {
    ethernet_t ethernet;
    //ipv4_t ipv4;
    //arp_t arp;
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
	    CPU_PORT: parse_packet_out; // if is packect-out packet then extract packet-out header
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
/*
	transition select(hdr.ethernet.etherType){
	    TYPE_IPV4: parse_ipv4;
	    TYPE_ARP: parse_arp;
	    default: accept;
	}
    }

    state parse_arp {
	packet.extract(hdr.arp);
	transition accept;
    }

    state parse_ipv4{
	packet.extract(hdr.ipv4);
	transition accept;

    }
*/
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
    action send_to_cpu(){    //digest to cpu
        digest<mac_learn_digest_t>((bit<32>) 10, 
	{hdr.ethernet.srcAddr, hdr.ethernet.dstAddr, 
	hdr.ethernet.etherType, (bit<16>)standard_metadata.ingress_port});
    }
    
    action flooding(){
	standard_metadata.mcast_grp = 1;    //controller will configue multicast group 1
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
	    if(standard_metadata.ingress_port == CPU_PORT){    //deal with packet-out packet
		debug_table.apply(); 
		standard_metadata.egress_spec = hdr.packet_out.egress_port;  //copy packet-out header to standard_metadata
		standard_metadata.mcast_grp = hdr.packet_out.mcast;
		hdr.packet_out.setInvalid();
	    }
	    else{    //deal with normal packet
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
	//packet.emit(hdr.arp);
	//packet.emit(hdr.ipv4);
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
