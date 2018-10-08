/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define DEBUG_TABLE

const bit<16> TYPE_IPV4 = 0x0800;
const bit<32> MAX_NUM = 1<<9;
const bit<32> I2E_ID = 9;
const bit<32> E2E_ID = 37;
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

struct metadata {
    bit<2> inflag;
    bit<2> eflag;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* TODO: add parser logic */
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
**************  Debug Table   *******************
*************************************************************************/

#ifdef DEBUG_TABLE

control debug_func(in standard_metadata_t standard_metadata)
{
    table dbg_table{
	key = {
	    standard_metadata.ingress_port: exact;
	    standard_metadata.egress_spec: exact;
	    standard_metadata.egress_port: exact;
	    standard_metadata.clone_spec: exact;
	    standard_metadata.instance_type: exact;
	    standard_metadata.drop: exact;
	    standard_metadata.recirculate_port: exact;
	    standard_metadata.packet_length: exact;
	    standard_metadata.enq_timestamp: exact;
	    standard_metadata.enq_qdepth: exact;
	    standard_metadata.deq_timedelta: exact;
	    standard_metadata.deq_qdepth: exact;
	    standard_metadata.ingress_global_timestamp: exact;
	    standard_metadata.egress_global_timestamp: exact;
	    standard_metadata.lf_field_list: exact;
	    standard_metadata.mcast_grp: exact;
	    standard_metadata.resubmit_flag: exact;
	    standard_metadata.egress_rid: exact;
	    standard_metadata.checksum_error: exact;
	    standard_metadata.recirculate_flag: exact;
	}
	actions = {
	    NoAction;
	}
	const default_action = NoAction();
    }
    apply{
        dbg_table.apply();
    }
}

#endif

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    #ifdef DEBUG_TABLE
	debug_func() debug_ingress;
    #endif
    action lan_forward(egressSpec_t port){
	standard_metadata.egress_spec = port;
    }

    table ipv4_lpm {
	key = {
	    hdr.ipv4.dstAddr: lpm;
	}
	actions = {
	    NoAction;
	    lan_forward;
	}
	size = 1024;
	default_action = NoAction();
    }
    
    apply {
	    #ifdef DEBUG_TABLE
		debug_ingress.apply(standard_metadata);
	    #endif
	    if(meta.inflag==0){
	    	meta.inflag = 1;
//		clone3(CloneType.I2E, I2E_ID, meta);
//		resubmit(meta);
	    }
	    else{
	        if(hdr.ipv4.isValid()){
	            ipv4_lpm.apply();
	        }
	    }
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    #ifdef DEBUG_TABLE
	debug_func() debug_egress;
    #endif

    apply {
	#ifdef DEBUG_TABLE
	debug_egress.apply(standard_metadata);
	#endif
	if(meta.eflag==0){
	    meta.eflag = 1;
	    clone3(CloneType.E2E, E2E_ID, meta);
//	    recirculate(meta);
	}
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
        /* TODO: add deparser logic */
	packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4);
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
