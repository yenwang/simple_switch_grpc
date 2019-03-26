#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_MPATH_LABEL = 0x0805; //randomly choose one private unused ether_type to represent the existence of Mpath_label header
const bit<16> TYPE_PATH_INFO = 0x8080; //randomly choose one private unused ether_type to represent the existence of PATH_INFO header

const bit<8> PROTO_UDP = 0x11;
const bit<8> PROTO_TCP = 0x06;

const bit<9> CPU_PORT = 255; //I specify 255 for cpu port while running simple_switch_grpc with command --cpu-port 255
const bit<32> PORT_NUM = 4;

register<bit<48>> ((bit<32>) 1) collect_register; // a timestamp register used to record last path info collection
register<bit<2>> ((bit<32>) 1) switch_type_register; //a register to record this switch is whice one of (edge, aggregation, core)
register<bit<8>> ((bit<32>) 1) switch_id_register; //a register to record the switch_id given by controller
register<bit<32>> (PORT_NUM) outport_counter_register; // a register used to maintain per port counter
register<bit<48>> (PORT_NUM) decayed_time_register; // a register used to record last time decayed per outport counter
register<bit<32>> (PORT_NUM) outport_util_register; //a register used to record per port util, but p4 doesn't suppoer floating

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

header mpath_label_t{
    bit<8> up_a_to_c;
    bit<8> down_c_to_a;
    bit<8> down_a_to_e;
    bit<8> down_e_to_h;
    bit<16> nextType;
}

header path_info_t{
    bit<8> src_edge_id;
    bit<8> src_aggregation_id;
    bit<8> core_id;
    bit<8> dst_aggregation_id;
    bit<8> dst_edge_id;
    bit<32> max_link_util;
    bit<16> nextType;
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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;    //for switch to carry the original ingress port of packet-in packet
    bit<7> padding;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;	   //for controller to tell switches to forward the packet-out packet through this field
    bit<16> mcast;	   //for controller to specify a multicast group if needed
    macAddr_t srcAddr;
    macAddr_t dstAddr;
    bit<7> padding;
}

struct metadata {
    bit<48> collect;
    bit<2> switch_type;
    bit<8> switch_id;
    bit<32> outport_counter;
    bit<48> decayed_time;
    bit<32> outport_util;
}

struct headers {
    ethernet_t ethernet;
    mpath_label_t mpath_label;
    path_info_t path_info;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
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
	transition select(hdr.ethernet.etherType){
	    TYPE_IPV4: parse_ipv4;
	    TYPE_MPATH_LABEL: parse_mpath_label;
	    default: accept;
	}
    }

    state parse_mpath_label {
	packet.extract(hdr.mpath_label);
	transition select(hdr.mpath_label.nextType){
	    TYPE_IPV4: parse_ipv4;
	    TYPE_PATH_INFO: parse_path_info;
	    default: accept;
	}
    }

    state parse_path_info {
	packet.extract(hdr.path_info);
	transition select(hdr.path_info.nextType){
	    TYPE_IPV4: parse_ipv4;
	    default: accept;
	}
    }

    state parse_ipv4 {
	packet.extract(hdr.ipv4);
	transition select(hdr.ipv4.protocol){
	    PROTO_TCP: parse_tcp;
	    PROTO_UDP: parse_udp;
	    default: accept;
	}
    }

    state parse_tcp {
	packet.extract(hdr.tcp);
	transition accept;
    }

    state parse_udp {
	packet.extract(hdr.udp);
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

    action drop(){
	mark_to_drop();
    }

    action normal_forward(egressSpec_t port){ //all hosts are in the same subnet
	standard_metadata.egress_spec = port;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action push_mpath_label_tcp(bit<8> down_c_to_a, bit<8> down_a_to_e, bit<8> down_e_to_h){
	hdr.mpath_label.setValid();

	//use 2 different hash functions to decide 2 upward output ports
	hash(standard_metadata.egress_spec,	
	     HashAlgorithm.crc16,
	     (bit<16>) 2,
	     { hdr.ipv4.srcAddr,
	       hdr.ipv4.dstAddr,
	       hdr.ipv4.protocol,
               hdr.tcp.srcPort,
	       hdr.tcp.dstPort },
	     (bit<32>) 1);

        hash(hdr.mpath_label.up_a_to_c,
             HashAlgorithm.crc32,
             (bit<16>) 2,
             { hdr.ipv4.srcAddr,
               hdr.ipv4.dstAddr,
               hdr.ipv4.protocol,
               hdr.tcp.srcPort,
               hdr.tcp.dstPort },
             (bit<32>) 1);
	hdr.mpath_label.down_c_to_a = down_c_to_a;
	hdr.mpath_label.down_a_to_e = down_a_to_e;
	hdr.mpath_label.down_e_to_h = down_e_to_h;
	hdr.mpath_label.nextType = hdr.ethernet.etherType;
	hdr.ethernet.etherType = TYPE_MPATH_LABEL;
    }

    action push_mpath_label_udp(bit<8> down_c_to_a, bit<8> down_a_to_e, bit<8> down_e_to_h){
	hdr.mpath_label.setValid();

	//use 2 different hash functions to decide 2 upward output ports
        hash(standard_metadata.egress_spec,
             HashAlgorithm.crc16,
             (bit<16>) 2,
             { hdr.ipv4.srcAddr,
               hdr.ipv4.dstAddr,
               hdr.ipv4.protocol,
               hdr.udp.srcPort,
               hdr.udp.dstPort },
               (bit<32>) 1);

        hash(hdr.mpath_label.up_a_to_c,
             HashAlgorithm.crc32,
             (bit<16>) 2,
             { hdr.ipv4.srcAddr,
               hdr.ipv4.dstAddr,
               hdr.ipv4.protocol,
               hdr.udp.srcPort,
               hdr.udp.dstPort },
               (bit<32>) 1);
	hdr.mpath_label.down_c_to_a = down_c_to_a;
	hdr.mpath_label.down_a_to_e = down_a_to_e;
	hdr.mpath_label.down_e_to_h = down_e_to_h;
	hdr.mpath_label.nextType = hdr.ethernet.etherType;
	hdr.ethernet.etherType = TYPE_MPATH_LABEL;
    }



    table tcp_processing{
	key = {
	    hdr.ipv4.dstAddr: exact;
	}
	actions = {
	    push_mpath_label_tcp;
	    normal_forward;
	    drop;
	    send_to_cpu;
	}
	size = 1024;
	default_action = drop();
    }

    table udp_processing{
	key = {
	    hdr.ipv4.dstAddr: exact;
	}
	actions = {
	    push_mpath_label_udp;
	    normal_forward;
	    drop;
	    send_to_cpu;
	}
	size = 1024;
	default_action = drop();
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
		hdr.ethernet.srcAddr = hdr.packet_out.srcAddr;
		hdr.ethernet.dstAddr = hdr.packet_out.dstAddr;
		hdr.packet_out.setInvalid();
	    }
	    else{ //deal with normal packet
		switch_type_register.read(meta.switch_type, (bit<32>) 0); //read switch type given by controller
		collect_register.read(meta.collect, (bit<32>) 0); //read last time path info collection time
		switch_id_register.read(meta.switch_id, (bit<32>) 0);
		if(hdr.mpath_label.isValid()){ //deal with mpath_label packet (src_aggr, core, dst_aggr, dst_edge)
		    //each follow-up switch extract relative field to forward
		    if(meta.switch_id == 0){ // (dst_edge)
			standard_metadata.egress_spec = (bit<9>) hdr.mpath_label.down_e_to_h;
			hdr.mpath_label.setInvalid(); //remove mpath_label
		    }
		    else if(meta.switch_id == 1){ // (src_aggr or dst_aggr)
			if(hdr.mpath_label.up_a_to_c != 0){ //src_aggr
			    standard_metadata.egress_spec = (bit<9>) hdr.mpath_label.up_a_to_c;
			    hdr.mpath_label.up_a_to_c = 0;
			}
			else{ //dst_aggr
			    standard_metadata.egress_spec = (bit<9>) hdr.mpath_label.down_a_to_e;
			}
		    }
		    else if(meta.switch_id == 2){ // (core)
			standard_metadata.egress_spec = (bit<9>) hdr.mpath_label.down_c_to_a;
		    }
		}
		else if(hdr.tcp.isValid()){ //deal with raw tcp packet sent by host (src_edge)
		    tcp_processing.apply();
		    if(standard_metadata.ingress_global_timestamp - meta.collect >= 1000000){ //do path info collection every 1 ms
			hdr.path_info.setValid();
			hdr.path_info.nextType = hdr.mpath_label.nextType;
			hdr.mpath_label.nextType = TYPE_PATH_INFO;
			hdr.path_info.src_edge_id = 0;
			hdr.path_info.src_aggregation_id = 0;
			collect_register.write((bit<32>) 0, standard_metadata.ingress_global_timestamp); //update last time of collecting path info
		    }
		}
		else if(hdr.udp.isValid()){ //deal with raw udp packet sent by host (src_edge)
		    udp_processing.apply();
		    if(standard_metadata.ingress_global_timestamp - meta.collect >= 1000000){ //do path info collection every 1 s
			hdr.path_info.setValid();
			hdr.path_info.nextType = hdr.mpath_label.nextType;
			hdr.mpath_label.nextType = TYPE_PATH_INFO;
			hdr.path_info.src_edge_id = 0;
			hdr.path_info.src_aggregation_id = 0;
			collect_register.write((bit<32>) 0, standard_metadata.ingress_global_timestamp); // update last time of collecting path info
		    }
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
    apply {
	decayed_time_register.read(meta.decayed_time, (bit<32>) standard_metadata.egress_port);
	outport_counter_register.read(meta.outport_counter, (bit<32>) standard_metadata.egress_port);//
	outport_util_register.read(meta.outport_util, (bit<32>) standard_metadata.egress_port);
	if(hdr.path_info.isValid()){
	    // append switch id to let controller collect traversed path
	    if(meta.switch_id == 0){ // (src_edge, dst_edge)
		if(hdr.path_info.src_edge_id == 0){ //src_edge
		    hdr.path_info.src_edge_id = meta.switch_id;
		}
		else{
		    hdr.path_info.dst_edge_id = meta.switch_id;
		    hdr.path_info.setInvalid(); //remove path_info header
		    //digest path_info to controller
		}
	    }
	    else if(meta.switch_id == 1){ //(src_aggr, dst_aggr)
		if(hdr.path_info.src_aggregation_id == 0){
		    hdr.path_info.src_aggregation_id = meta.switch_id;
		}
		else {
		    hdr.path_info.dst_aggregation_id = meta.switch_id;
		}
	    }
	    else if(meta.switch_id == 2){ // core
		hdr.path_info.core_id = meta.switch_id;
	    }
	    if(meta.outport_util > hdr.path_info.max_link_util){ //update header's max link util
		hdr.path_info.max_link_util = meta.outport_util;
	    }
	}

	if(standard_metadata.egress_global_timestamp - meta.decayed_time >= 1000000){ // if now_time - last_time_decayed >= 1s , decay counter (/2)
	    meta.outport_counter = meta.outport_counter >> 1; // decay counter
	    meta.outport_counter = meta.outport_counter + standard_metadata.packet_length; //counter accumulation (bytes)
	    //calculate outport link util (question: no floating point support in p4), split through 8 ranges
	    outport_counter_register.write((bit<32>) standard_metadata.egress_port, meta.outport_counter);
	}
	else {
	    meta.outport_counter = meta.outport_counter + standard_metadata.packet_length;
	    outport_counter_register.write((bit<32>) standard_metadata.egress_port, meta.outport_counter);
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
        packet.emit(hdr.packet_in);
	packet.emit(hdr.ethernet);
	packet.emit(hdr.mpath_label);
	packet.emit(hdr.path_info);
	packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
	packet.emit(hdr.udp);
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
