/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> TYPE_ICMP = 0x01;
const bit<8> TYPE_TCP = 0x06;
const bit<32> MAX_NUM = 1;
typedef bit<8> REGISTER_TYPE;
register<REGISTER_TYPE>(MAX_NUM) ingress_register;
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

header icmp_t {
    bit<8>    type;
    bit<8>    code;
    bit<16>   checksum;
    bit<16>   id;
    bit<16>   sequence;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header did_t {
    bit<8>    device_id;
}

struct metadata {
    ip4Addr_t nhop_ip;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
    tcp_t        tcp;
    did_t        did;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
	packet.extract(hdr.ethernet);
	transition select(hdr.ethernet.etherType) {
	    TYPE_IPV4: parse_ipv4;
	    default: accept;
	}
    }
    state parse_ipv4{
	packet.extract(hdr.ipv4);
	transition select(hdr.ipv4.protocol) {
	    TYPE_ICMP: parse_icmp;
	    TYPE_TCP: parse_tcp;
	    default: accept;
	}
    }
    state parse_icmp{
	packet.extract(hdr.icmp);
	transition accept;
    }
    state parse_tcp{
	packet.extract(hdr.tcp);
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
    action drop() {
        mark_to_drop();
    }

    action set_nhop(ip4Addr_t nhop){
	meta.nhop_ip = nhop;
    }

    action forward(egressSpec_t port, macAddr_t dmac){
	standard_metadata.egress_spec = port;
	hdr.ethernet.dstAddr = dmac;
    }

    table ipv4_lpm {
	key = {
	    hdr.ipv4.dstAddr: lpm;
	}
	actions = {
	    drop;
	    NoAction;
	    set_nhop;
	}
	size = 1024;
	default_action = NoAction();
    }

    table nhop_exact {
	key = {
	    meta.nhop_ip: exact;
	}
	actions = {
	    drop;
	    NoAction;
	    forward;
	}
	size = 1024;
	default_action = NoAction();
    }
    
    apply {
	//ingress_register.write((bit<32>) 0, port);
	if(hdr.ipv4.isValid()){
	    ipv4_lpm.apply();
	    if((hdr.ipv4.srcAddr & 4294967040) == (hdr.ipv4.dstAddr & 4294967040)){
	        hdr.ethernet.srcAddr = hdr.ethernet.srcAddr;
	    }
	    else {hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;}
	    nhop_exact.apply();
	    if(hdr.tcp.isValid()){
		hdr.did.setValid();
		ingress_register.read(hdr.did.device_id, 0);
	    }
	    else {}
	}
	else {}
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
	//ingress_register.write(0, 100);
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {

	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
	packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4);
	packet.emit(hdr.icmp);
	packet.emit(hdr.tcp);
	packet.emit(hdr.did);
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
