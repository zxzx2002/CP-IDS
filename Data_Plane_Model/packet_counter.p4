#include <core.p4>
#include <v1model.p4>
#include <tna.p4>

#define CPU_PORT 255
#define PORT_METADATA_SIZE 32

const bit<16> ETHERTYPE_IPV4 = 0x0800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header gtp_t {
    bit<8>  flags;
    bit<8>  msgType;
    bit<16> length;
    bit<32> teid;
}

header gtp_optional_t{
    bit<8> sequence_number_1;
    bit<8> sequence_number_2;
    bit<8> N_PDU;
    bit<8> next_extension_header_type;
}

header extension_header_t{
    bit<8> length;
    bit<8> pdu_session;
    bit<8> QFI;
    bit<8> extension_header;
}

struct metadata {
    bit<32> num;
    bit<16> add;
    bit<16> sub;
    bit<32> packet_length;
    bit<32> read_packet_count;  
    bit<32> read_byte_count;    
    bit<32> packet_count;
    bit<32> byte_count;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
    gtp_t        gtp;   
    gtp_optional_t gtp_optional;
    extension_header_t extension_header;
    ipv4_t       inner_ipv4;
    udp_t        inner_udp;
}

/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

// Tofino intrinsic parser
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packets
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

// Main ingress parser
parser MyIngressParser(packet_in packet,
                out headers hdr,
		        out metadata meta,
                out ingress_intrinsic_metadata_t ig_intr_md)
{
    TofinoIngressParser() tofino_parser;
    state start {
        tofino_parser.apply(packet, ig_intr_md);//Standard boilerplate call
        transition parse_ethernet;
    }



    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            6 : parse_tcp;//Added
            default: accept;
        }
    }
    state parse_tcp { //Added
    packet.extract(hdr.tcp);
    transition accept;
}

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            2152: parse_gtp;
            default: accept;
        }
    }

    state parse_gtp {
        packet.extract(hdr.gtp);
        transition select(hdr.gtp.flags) {
            0x34: parse_gtp_optional;
            default: accept;
        }
    }

    state parse_gtp_optional {
        packet.extract(hdr.gtp_optional);
        transition select(hdr.gtp_optional.next_extension_header_type) {
            0x85: parse_extension_header;
            default: accept;
        }
    }

    state parse_extension_header {
        packet.extract(hdr.extension_header);
        transition select(hdr.extension_header.QFI){
            1: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            17: parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }
}

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

    // -----------------------------------------------------------------------
    // 1. Define packet counter: Check if > internally within the register> 10
    //    Change U (Output) type to bit<1>, used to return the limit exceeded flag
    // -----------------------------------------------------------------------
    Register<bit<32>, bit<32>>(1) packet_counter;
    RegisterAction<bit<32>, bit<32>, bit<1>>(packet_counter)
        packet_counter_action = {
            // apply returns bit<1>: 1 means limit exceeded, 0 means normal
            void apply(inout bit<32> val, out bit<1> is_limit_exceeded) {
                // Increment
                val = val + 1;
                // Use register ALU for direct comparison
                if (val > 10) {
                    is_limit_exceeded = 1;
                } else {
                    is_limit_exceeded = 0;
                }
            }
        };

    // -----------------------------------------------------------------------
    // 2. Define byte counter: Check if > 5000 internally within the register> 5000
    // -----------------------------------------------------------------------
    Register<bit<32>, bit<32>>(1) byte_counter;
    RegisterAction<bit<32>, bit<32>, bit<1>>(byte_counter)
        byte_counter_action = {
            void apply(inout bit<32> val, out bit<1> is_limit_exceeded) {
                // Accumulate packet length
                val = val + meta.packet_length;
                // Use register ALU for direct comparison
                if (val > 5000) {
                    is_limit_exceeded = 1;
                } else {
                    is_limit_exceeded = 0;
                }
            }
        };

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action set_egress_port(bit<9> egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;
    }

    apply {
        // Declare local variables to receive the 1-bit result from the register to avoid modifying PHV fields
        bit<1> pkt_limit_flag;
        bit<1> byte_limit_flag;

        // 1. 1. Initialize packet length
        if (hdr.ipv4.isValid()) {
            meta.packet_length = (bit<32>)hdr.ipv4.total_len;
        } else {
            meta.packet_length = 64;
        }

        // 2. Update counters and get the "limit exceeded" flag
        pkt_limit_flag = packet_counter_action.execute(0);
        byte_limit_flag = byte_counter_action.execute(0);

        // 3. Check flags and drop packet
        // Only compare 1-bit variables here, fully complying with Tofino pipeline constraints
        if (pkt_limit_flag == 1) {
            drop();
        } 
        else if (byte_limit_flag == 1) {
            drop();
        } 
        else {
            set_egress_port(12);
        }
    }
}
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyIngressDeparser(packet_out packet,
     inout headers hdr,
    in metadata meta,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)  {

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp);
        packet.emit(hdr.gtp_optional);
        packet.emit(hdr.extension_header);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_udp);
    }
}

/*************************************************************************
*********************** E G R E S S  P A R S E R  ***********************
*************************************************************************/

parser MyEgressParser(
       packet_in packet,
        out headers hdr,
        out metadata meta,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            2152: parse_gtp;
            default: accept;
        }
    }

    state parse_gtp {
        packet.extract(hdr.gtp);
        transition select(hdr.gtp.flags) {
            0x34: parse_gtp_optional;
            default: accept;
        }
    }

    state parse_gtp_optional {
        packet.extract(hdr.gtp_optional);
        transition select(hdr.gtp_optional.next_extension_header_type) {
            0x85: parse_extension_header;
            default: accept;
        }
    }

    state parse_extension_header {
        packet.extract(hdr.extension_header);
        transition select(hdr.extension_header.QFI) {
            1: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            17: parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }
}

/*************************************************************************
*********************** E G R E S S  D E P A R S E R  *******************
*************************************************************************/

control MyEgress(inout headers hdr,
    inout metadata meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md){
    apply{}
}

control MyEgressDeparser(
        packet_out packet,
        inout headers hdr,
        in metadata meta,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp);
        packet.emit(hdr.gtp_optional);
        packet.emit(hdr.extension_header);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_udp);
    }
}

/*************************************************************************
*********************** S W I T C H  ************************************
*************************************************************************/

Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;
Switch(pipe) main;