#include <core.p4>
#include <t2na.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

#define SKETCH_BUCKET_LENGTH 2
#define SKETCH_CELL_BIT_WIDTH 64

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    Register<bit<SKETCH_CELL_BIT_WIDTH>, bit<32>>(SKETCH_BUCKET_LENGTH) bloomfilter;\
    RegisterAction<bit<64>, bit<32>, bit<64>>(bloomfilter) 
        action_bloomfilter = {
            void apply(inout bit<64> value_bloomfilter, out bit<64> read_value_bloomfilter) {
                value_bloomfilter = 1;
                read_value_bloomfilter = value_bloomfilter;
            }};
    RegisterAction<bit<64>, bit<32>, bit<64>>(bloomfilter) 
        action_read_bloomfilter = {
            void apply(inout bit<64> value_bloomfilter, out bit<64> read_value_bloomfilter) {
                read_value_bloomfilter = value_bloomfilter;
            }};

    CRCPolynomial<bit<32>>(32w0xEDB88320, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly) myhash;

    action check_bloomfilter() {
        meta.index_sketch = (myhash.get({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x0001; //&15，相当于取余16，把结果收缩到0-15里面
    }

    table tbl_bloomfilter {
        actions = {check_bloomfilter;}
        size = 1;
        const default_action = check_bloomfilter();
    }
/*************************************************************************
**************  M Y  C O N T R O L  P R O G R A M  *******************
*************************************************************************/

    action read_sketch(bit<32> index) {
        hdr.myTunnel.load_sketch = action_read_bloomfilter.execute(index);
    }

    action drop(){
		ig_dprsr_md.drop_ctl = 0x1;
	}

    action set_egress_port(bit<9> egress_port){
        ig_tm_md.ucast_egress_port = egress_port;
    }

    table forwarding {
        key = {ig_intr_md.ingress_port: exact;}
        actions = {set_egress_port; drop; NoAction;}
        size = 64;
        default_action = drop;
    }

     action send_to_cpu() {
        ig_tm_md.copy_to_cpu = 1w1;
    }

    action add_header(){
        hdr.myTunnel.setValid();
        hdr.myTunnel.proto_id = TYPE_IPV4;
	    hdr.ethernet.etherType = TYPE_MYTUNNEL;
        //注意添加包头之后，解析顺序要与parser.p4一致
    }

    action del_header(){
        hdr.myTunnel.setInvalid();
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    apply {
        tbl_bloomfilter.apply();
        if(!hdr.myTunnel.isValid()){
            action_bloomfilter.execute(meta.index_sketch);
            //add_header();
            drop();
        }
        else if(hdr.myTunnel.isValid()){
            read_sketch(meta.index_sketch);
            send_to_cpu();
            forwarding.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
	inout metadata meta,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
	inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md){
	apply{}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;
Switch(pipe) main;