#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<8> PROTO_UDP = 0x11;
//int related
const bit<6> INT_DSCP = 6w1;
const bit<8> INT_HEADER_LEN_WORD = 4;
//register related
const bit<32> MAX_NUM = 1;
typedef bit<32> REGISTER_TYPE;
register<REGISTER_TYPE>(MAX_NUM) switch_id;

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

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   len;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
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

header int_header_t {
    bit<2> ver;
    bit<2> rep;
    bit<1> c;
    bit<1> e;
    bit<5> rsvd1;
    bit<5> ins_cnt;
    bit<8> max_hop_cnt;
    bit<8> total_hop_cnt; // number of switch that have appended metadata
    bit<4> inst_mask_0003;
    bit<4> inst_mask_0407;
    bit<4> inst_mask_0811;
    bit<4> inst_mask_1215;
    bit<16> rsvd2;
}

header int_shim_t {
    bit<8> int_type;
    bit<8> rsvd1;
    bit<8> len;
    bit<8> rsvd2;
}

header int_tail_t {
    bit<8> proto;
    bit<16> dst_port;
    bit<8> dscp;
}

header int_switch_id_t { //bit 0
    bit<32> switch_id;
}

header int_port_ids_t { //bit 1
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}

header int_hop_latency_t { //bit2
    bit<32> hop_latency;
}

header int_queue_occupancy_t { //bit3
    bit<8> qid;
    bit<24> queue_occupancy;
}

header int_ingress_timestamp_t { //bit4
    bit<32> ingress_timestamp;
}

header int_egress_timestamp_t{ //bit5
    bit<32> egress_timestamp;
}

header int_queue_congestion_status_t{ //bit 6
    bit<8> qid;
    bit<24> queue_congestion_status;
}

header int_egress_port_tx_util_t{ //bit7
    bit<32> egress_port_tx_util;
}

header int_data_t {
    varbit<8032> int_data;
}

struct metadata {
    bit<1> int_source;
    bit<1> int_sink;
    bit<1> int_selector;
    bit<5> ins_cnt;
    bit<8> max_hop_cnt;
    bit<4> inst_mask_0003;
    bit<4> inst_mask_0407;
    bit<16> insert_byte_cnt;

}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    packet_in_header_t packet_in;
    packet_out_header_t packet_out;
    int_header_t int_header;
    int_shim_t int_shim;
    int_tail_t int_tail;
    int_switch_id_t int_switch_id;
    int_port_ids_t int_port_ids;
    int_hop_latency_t int_hop_latency;
    int_queue_occupancy_t int_queue_occupancy;
    int_ingress_timestamp_t int_ingress_timestamp;
    int_egress_timestamp_t int_egress_timestamp;
    int_queue_congestion_status_t int_queue_congestion_status;
    int_egress_port_tx_util_t int_egress_port_tx_util;
    int_data_t int_data;
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
	    default: accept;
	}
    }

    state parse_ipv4{
	packet.extract(hdr.ipv4);
	transition select(hdr.ipv4.protocol){
	    PROTO_UDP: parse_udp;
	    default: accept;
	}
    }

    state parse_udp{
	packet.extract(hdr.udp);
	transition select(hdr.ipv4.dscp == INT_DSCP){
	    true: parse_int_shim;
	    default: accept;
	}
    }

    state parse_int_shim{
	packet.extract(hdr.int_shim);
	transition parse_int_header;
    }

    state parse_int_header{
	packet.extract(hdr.int_header);
	transition parse_int_data;
    }

    state parse_int_data {
	packet.extract(hdr.int_data, (bit<32>) ((hdr.int_shim.len - INT_HEADER_LEN_WORD) << 5));
	transition parse_int_tail;
    }

    state parse_int_tail {
	packet.extract(hdr.int_tail);
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

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port){
	standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action int_selection(bit<1> int_selector, bit<5> ins_cnt, bit<8> max_hop_cnt, bit<4> inst_mask_0003, bit<4> inst_mask_0407){
	meta.int_selector = int_selector;
	meta.ins_cnt = ins_cnt;
	meta.max_hop_cnt = max_hop_cnt;
	meta.inst_mask_0003 = inst_mask_0003;
	meta.inst_mask_0407 = inst_mask_0407;
    }

    action int_set_source(bit<1> int_source){
	meta.int_source = int_source;
    }

    action int_set_sink(bit<1> int_sink){
	meta.int_sink = int_sink;
    }

    table set_sink_table{
	key = {
	    standard_metadata.egress_port: exact;
	}
	actions = {
	    int_set_sink;
	    NoAction;
	}
	size = 1024;
	default_action = NoAction();
    }

    table set_source_table{
	key = {
	    standard_metadata.ingress_port: exact;
	}
	actions = {
	    int_set_source;
	    NoAction;
	}
	size = 1024;
	default_action = NoAction();
    }

    table int_control_table{
	key = {
	    hdr.ipv4.srcAddr: exact;
	    hdr.ipv4.dstAddr: exact;
	    hdr.ipv4.protocol: exact;
	    hdr.udp.src_port: exact;
	    hdr.udp.dst_port: exact;
	}
	actions = {
	    int_selection;
	    NoAction;
	}
	size = 1024;
	default_action = NoAction();
    }

    table ipv4_lpm{
	key = {
	    hdr.ipv4.dstAddr: exact;
	}
	actions = {
	    ipv4_forward;
	    drop;
	    send_to_cpu;
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
		hdr.ethernet.srcAddr = hdr.packet_out.srcAddr;
		hdr.ethernet.dstAddr = hdr.packet_out.dstAddr;
		hdr.packet_out.setInvalid();
	    }
	    else{    //deal with normal packet
		if(hdr.ipv4.isValid()){
		    ipv4_lpm.apply(); //look-up ip_dst to decide egress_spec
		    if(hdr.udp.isValid()){
			int_control_table.apply(); //int_source has to look-up five dimensions to set int_selector
			if((meta.int_selector == 1) || (hdr.ipv4.dscp == INT_DSCP)){ //whether switch should do int or not
			    set_source_table.apply(); // if in_port is host then this switch is int_source
			    set_sink_table.apply(); // if egress spec is host then this switch is int_sink
			}
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

    action int_set_header_0(){ //set switch_id
	hdr.int_switch_id.setValid();
	switch_id.read(hdr.int_switch_id.switch_id, 0); //set int_switch_id by reading register switch_id
    }
    action int_set_header_1(){ //set port_ids
	hdr.int_port_ids.setValid();
	hdr.int_port_ids.ingress_port_id = (bit<16>) standard_metadata.ingress_port;
	hdr.int_port_ids.egress_port_id = (bit<16>) standard_metadata.egress_port;
    }
    action int_set_header_2(){ //set hop_latency
	hdr.int_hop_latency.setValid();
	hdr.int_hop_latency.hop_latency = (bit<32>) (standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp);
    }
    action int_set_header_3(){ //set queue_occupancy
	hdr.int_queue_occupancy.setValid();
	hdr.int_queue_occupancy.qid = (bit<8>) standard_metadata.egress_port;
	hdr.int_queue_occupancy.queue_occupancy = (bit<24>) standard_metadata.deq_qdepth;
    }
    action int_set_header_4(){ //set ingress_timestamp
	hdr.int_ingress_timestamp.setValid();
	hdr.int_ingress_timestamp.ingress_timestamp = (bit<32>) standard_metadata.ingress_global_timestamp;
    }
    action int_set_header_5(){ //set egress_timestamp
	hdr.int_egress_timestamp.setValid();
	hdr.int_egress_timestamp.egress_timestamp = (bit<32>) standard_metadata.egress_global_timestamp;
    }
    action int_set_header_6(){ //set queue_congestion
	hdr.int_queue_congestion_status.setValid();
	hdr.int_queue_congestion_status.qid = (bit<8>) standard_metadata.egress_port;
	hdr.int_queue_congestion_status.queue_congestion_status =(bit<24>) standard_metadata.deq_qdepth;
    }
    action int_set_header_7(){ //set egress_port_tx_utilization
	hdr.int_egress_port_tx_util.setValid();
	// todo
    }

    // action function for bits 0-3 combinations
    action int_set_header_0003_i0() {
    }
    action int_set_header_0003_i1() {
        int_set_header_3();
    }
    action int_set_header_0003_i2() {
        int_set_header_2();
    }
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
    }
    action int_set_header_0003_i4() {
        int_set_header_1();
    }
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
    }
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
    }
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
    }
    action int_set_header_0003_i8() {
        int_set_header_0();
    }
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
    }
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
    }
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
    }
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
    }
    //action function for bits 4-7 combination
    action int_set_header_0407_i0() {
    }
    action int_set_header_0407_i1() {
        int_set_header_7();
    }
    action int_set_header_0407_i2() {
        int_set_header_6();
    }
    action int_set_header_0407_i3() {
        int_set_header_7();
        int_set_header_6();
    }
    action int_set_header_0407_i4() {
        int_set_header_5();
    }
    action int_set_header_0407_i5() {
        int_set_header_7();
        int_set_header_5();
    }
    action int_set_header_0407_i6() {
        int_set_header_6();
        int_set_header_5();
    }
    action int_set_header_0407_i7() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
    }
    action int_set_header_0407_i8() {
        int_set_header_4();
    }
    action int_set_header_0407_i9() {
        int_set_header_7();
        int_set_header_4();
    }
    action int_set_header_0407_i10() {
        int_set_header_6();
        int_set_header_4();
    }
    action int_set_header_0407_i11() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_4();
    }
    action int_set_header_0407_i12() {
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i13() {
        int_set_header_7();
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i14() {
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i15() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
    }

    table int_inst_0407{
	key = {
	    hdr.int_header.inst_mask_0407: exact;
	}
	actions = {
	    int_set_header_0407_i0;
            int_set_header_0407_i1;
            int_set_header_0407_i2;
            int_set_header_0407_i3;
            int_set_header_0407_i4;
            int_set_header_0407_i5;
            int_set_header_0407_i6;
            int_set_header_0407_i7;
            int_set_header_0407_i8;
            int_set_header_0407_i9;
            int_set_header_0407_i10;
            int_set_header_0407_i11;
            int_set_header_0407_i12;
            int_set_header_0407_i13;
            int_set_header_0407_i14;
            int_set_header_0407_i15;
	}
	size = 16;
    }

    table int_inst_0003{
	key = {
	    hdr.int_header.inst_mask_0003: exact;
	}
	actions = {
	    int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
	}
	size = 16;
    }

    apply {
	if((standard_metadata.ingress_port != CPU_PORT) && ((meta.int_selector == 1) || (hdr.ipv4.dscp == INT_DSCP))){ //if switch has to do int operation
	    if(meta.int_source == 1){ // INT source
		//set shim header
		hdr.int_shim.setValid();
		hdr.int_shim.int_type = 1;
		hdr.int_shim.len = INT_HEADER_LEN_WORD;
		//set INT header
		hdr.int_header.setValid();
		hdr.int_header.ver = 0;
		hdr.int_header.rep = 0;
		hdr.int_header.c = 0;
		hdr.int_header.e = 0;
		hdr.int_header.rsvd1 = 0;
		hdr.int_header.ins_cnt = meta.ins_cnt;
		hdr.int_header.max_hop_cnt = meta.max_hop_cnt;
		hdr.int_header.total_hop_cnt = 0;
		hdr.int_header.inst_mask_0003 = meta.inst_mask_0003;
		hdr.int_header.inst_mask_0407 = meta.inst_mask_0407;
		hdr.int_header.inst_mask_0811 = 0; //not supported yet
		hdr.int_header.inst_mask_1215 = 0; //not supported yet
		//set INT tail
		hdr.int_tail.setValid();
		hdr.int_tail.proto = hdr.ipv4.protocol;
		hdr.int_tail.dst_port = hdr.udp.dst_port;
		hdr.int_tail.dscp = (bit<8>) hdr.ipv4.dscp;
		//adjust packet length indication
		hdr.ipv4.len = hdr.ipv4.len + 16;
		hdr.udp.len = hdr.udp.len + 16;
		// set dscp
		hdr.ipv4.dscp = INT_DSCP;
	    }
	    if(hdr.int_header.isValid()){ // every INT switch
		//append correspond metadata
		int_inst_0003.apply();
		int_inst_0407.apply();
		// update INT header & ipv4&udp len field
		hdr.int_header.total_hop_cnt = hdr.int_header.total_hop_cnt + 1;
		meta.insert_byte_cnt = (bit<16>) (hdr.int_header.ins_cnt << 2);
		hdr.ipv4.len = hdr.ipv4.len + meta.insert_byte_cnt;
		hdr.udp.len = hdr.udp.len + meta.insert_byte_cnt;
		//update INT shim header len
		hdr.int_shim.len = hdr.int_shim.len + (bit<8>) hdr.int_header.ins_cnt;

		if(meta.int_sink == 1){ //INT sink
		    //restore udp dst_port & ipv4 dscp
		    hdr.udp.dst_port = hdr.int_tail.dst_port;
		    hdr.ipv4.dscp = (bit<6>) hdr.int_tail.dscp;
		    //restore ipv4&udp len field
		    hdr.ipv4.len = hdr.ipv4.len - (bit<16>) ((hdr.int_shim.len - (bit<8>) hdr.int_header.ins_cnt) << 2);
		    hdr.udp.len = hdr.udp.len - (bit<16>) ((hdr.int_shim.len - (bit<8>) hdr.int_header.ins_cnt) << 2);
		    //remove INT related headers
		    hdr.int_shim.setInvalid();
		    hdr.int_header.setInvalid();
		    hdr.int_switch_id.setInvalid();
		    hdr.int_port_ids.setInvalid();
		    hdr.int_hop_latency.setInvalid();
		    hdr.int_queue_occupancy.setInvalid();
		    hdr.int_ingress_timestamp.setInvalid();
		    hdr.int_egress_timestamp.setInvalid();
		    hdr.int_queue_congestion_status.setInvalid();
		    hdr.int_egress_port_tx_util.setInvalid();
		    hdr.int_data.setInvalid();
		    hdr.int_tail.setInvalid();
		}
	    }
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
              hdr.ipv4.dscp,
	      hdr.ipv4.ecn,
              hdr.ipv4.len,
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
	packet.emit(hdr.ipv4);
	packet.emit(hdr.udp);
	packet.emit(hdr.int_shim);
	packet.emit(hdr.int_header);
	packet.emit(hdr.int_switch_id);
	packet.emit(hdr.int_port_ids);
	packet.emit(hdr.int_hop_latency);
	packet.emit(hdr.int_queue_occupancy);
	packet.emit(hdr.int_ingress_timestamp);
	packet.emit(hdr.int_egress_timestamp);
	packet.emit(hdr.int_queue_congestion_status);
	packet.emit(hdr.int_egress_port_tx_util);
	packet.emit(hdr.int_data);
	packet.emit(hdr.int_tail);
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
