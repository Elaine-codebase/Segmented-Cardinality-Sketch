#include "includes/headers.p4"
#include "includes/parser.p4"
#include <tofino/intrinsic_metadata.p4> // data
#include <tofino/constants.p4>
#include <tofino/lpf_blackbox.p4>
#include <tofino/stateful_alu_blackbox.p4>

 
//#define rowSize 4
#define colSize 512
#define bitmap_size 256
//#define oldbitmap_size 256
@pragma stage 0
table forward_ipv4 {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        set_egr; nop;
    }
    max_size : 512;
}

action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}
// Define header structure for IPv4
header_type metadata_t {
    fields {
        src_addr : 32;   // 源 IP 地址
        dst_addr : 32;   // 目标 IP 地址
        //left    : 1;    // 协议
       // right   : 1;    // 存活时间
       // depth:5;
       // right_has :1;
       // left_has:1;
        cardinality:5;
        loc_1:16;
        loc_2:16;
        key_1             : 32;
        count_1           : 32;
        key_2             : 32;
        cur_timestamp: 32;
        count_2           : 32;

        result_binary: 32;
        is_new_pkt: 16;

        bl_hash_res1: 1;  // First Hash Res
        bl_hash_res2: 1;  // Second Hash Res
        bl_hash_res3: 1;  // Third Hash Res

        cell1_index: 2;   // the col index of first row
        cell2_index: 2;   // the col index of second row

        mask1: 8;         // the first mask
        mask2: 8;         // the second mask
        mask3: 8;         // the third mask

        resubmit: 1;      // 是否为重提交数据包

    }
}metadata metadata_t mdata;

// Define registers for storing source and destination IP, and bitmap

register bitmap_array {
    width: 8;
    instance_count: bitmap_size;
       attributes : saturating;
}
register bitmap_array_data {
    width: 8;
    instance_count: bitmap_size;
       attributes : saturating;
}
//register bitmap_depth {
  //  width: 16;
  //  instance_count: 1;
  //     attributes : saturating;
//}

//blackbox stateful_alu update_bitmap_depth{
  //  reg : bitmap_depth;
    
   // update_lo_1_value : register_lo + 1;
 
   

   // output_value : alu_lo; //read key to check whether successful update 
   // output_dst : mdata.key_2;
//
  //  initial_register_lo_value : 0;
  //  initial_register_hi_value : 0;
//}
//action do_update_bitmap_depth(){
  //  update_bitmap_depth.execute_stateful_alu(mdata.loc_2);
//}
//table tb_do_update_bitmap_depth {
  //  actions { do_update_bitmap_depth; }
   // default_action : do_update_bitmap_depth();
//}


blackbox stateful_alu update_bitmap_array{
    reg : bitmap_array;

    update_lo_1_value : register_lo + 1;

    initial_register_lo_value : 0;
    initial_register_hi_value : 0;
}
action do_update_bitmap_array(){
    update_bitmap_array.execute_stateful_alu(mdata. loc_2);
}
@pragma stage 2
table tb_do_update_topk_array {
    actions { do_update_bitmap_array; }
    default_action : do_update_bitmap_array();
}


// Define action to set left existence
//action set_left_true() {
   // modify_field(mdata.left_has, 1);
//}

//action set_left_false() {
   // modify_field(mdata.left_has, 0);
//}

//action set_right_true() {
   // modify_field(mdata.right_has, 1);
//}

//action set_right_false() {
  //  modify_field(mdata.right_has, 0);
//}

 
// 递增深度
 
action nop() {
}
// Define action to stop recursion
//action stop_recursion() {
   // nop();
//}
action get_src_ip() {
    modify_field(mdata.src_addr, ipv4.srcAddr);
}

action get_dst_ip() {
    modify_field(mdata.dst_addr, ipv4.dstAddr);
}
@pragma stage 0
table get_ip_table {
    actions { get_src_ip; get_dst_ip; }
    default_action :get_src_ip;
}

// Define the hash calculation function
field_list hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    udp.srcPort;
    udp.dstPort;
}

// Define hash function
field_list_calculation sketch_hash_r1 {
    input {
        hash_fields;
    }
    algorithm : crc_16;
    output_width : 16;
}

field_list_calculation sketch_hash_r2 {
    input {
        hash_fields;
    }
    algorithm : crc_16_buypass;
    output_width : 16;
}

// Define table for checking source IP hash
@pragma stage 1
table check_src_ip_hash_table {
        reads  {
       mdata.src_addr : exact;
    }
    actions  { update_src_ip_hash; }

    size : 1024;
}

action update_src_ip_hash() {
       modify_field_with_hash_based_offset(mdata.src_addr, 0, sketch_hash_r2, colSize);
    
}

 
 
 
register bucket_array_1{
    width : 64; // <key,value>
    instance_count : colSize;
    attributes : saturating;
}
action get_locs1(){
    modify_field_with_hash_based_offset(mdata.loc_1, 0, sketch_hash_r2, colSize);
}
blackbox stateful_alu update_bucket_array_1{
    reg : bucket_array_1;
    condition_lo : register_lo == 0; // Is this bucket empty?
    condition_hi : register_hi == mdata.src_addr; //Does this bucket store the flow?
    update_lo_1_predicate : condition_lo or condition_hi; // it is empty or hit
    update_lo_1_value : register_lo + 1;
    update_lo_2_predicate : not condition_lo and not condition_hi; // else read
    update_lo_2_value : register_lo;

    update_hi_1_predicate : condition_lo or condition_hi; // it is empty or hit
    update_hi_1_value :  mdata.src_addr;
    update_hi_2_predicate : not condition_lo and not condition_hi; // else read 
    update_hi_2_value : register_hi;

    output_value : alu_hi; //read key to check whether successful update 
    output_dst : mdata.key_1;

    initial_register_lo_value : 0;
    initial_register_hi_value : 0;
}
action set_new_flag(tmp){
    modify_field(mdata.is_new_pkt,tmp);
}
@pragma stage 0
table tb_set_new_flag{
    reads{
        mdata.result_binary: ternary;
        mdata.cur_timestamp: exact;
    }
    actions{
        set_new_flag;
    }
    size: 8;
}

action do_update_bucket_array_1(){
    update_bucket_array_1.execute_stateful_alu(mdata.loc_1);
}
@pragma stage 3
table array_1_table {
    actions { do_update_bucket_array_1; }
    default_action : do_update_bucket_array_1();
}

register bucket_array_1_data{
    width : 32; // value
    instance_count : colSize ;
    attributes : saturating;
}

blackbox stateful_alu read_bucket_array_1_data{
    reg : bucket_array_1_data;

    update_lo_1_value: register_lo;
    output_value : register_lo; //read counter vlaue
    output_dst : mdata.count_1;

    initial_register_lo_value : 0;
}

action do_read_bucket_array_1_data(){
    read_bucket_array_1_data.execute_stateful_alu(mdata.loc_1);
}
@pragma stage 4
table array_1_data_table {
    actions { do_read_bucket_array_1_data; }
    default_action : do_read_bucket_array_1_data();
}
 
 
blackbox stateful_alu read_bitmap_array_1_data{
    reg : bitmap_array_data;

    update_lo_1_value: register_lo;
    output_value : register_lo; //read counter vlaue
    output_dst : mdata.count_1;

    initial_register_lo_value : 0;
}

action do_read_bitmap_array_1_data(){
    read_bitmap_array_1_data.execute_stateful_alu(mdata.loc_1);
}
//@pragma stage 3
//table tb_bitmap1_data_table {
  //  actions { do_read_bitmap_array_1_data; }
   // default_action : do_read_bitmap_array_1_data();
//}
 

// Define table for checking depth and boundary
//table check_depth_and_boundary_table {
  //      reads {
  //      mdata.left_has : exact;
  //      mdata.right_has : exact;
  //  }
  //  actions  { do_update_bitmap_depth; stop_recursion; }

 //   size :4;
//}

 
 
// Define table for checking cardinality
@pragma stage 3
table cardinality_check_table {
    reads {
        mdata.cardinality : exact;
       // mdata.depth : exact;
    }
    actions {do_read_bitmap_array_1_data;  }
    size : 1024;
}

 
// Define parser
//parser start {
   // extract(ipv4);
   // transition ingress;  // 进入 ingress 控制
//}

// Define tables for packet processing
@pragma stage 4
table forward {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        //set_egr;
        nop;
    }
    max_size : 512;
}
@pragma stage 4
 table forward_nop{
    actions{nop;}
 } 
 @pragma stage 4
table forward_arp {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        //set_egr;
        nop;
    }
}

table acl {
    reads {
        ethernet.dstAddr : ternary;
        ethernet.srcAddr : ternary;
    }
    actions {
        nop;
    
    }
}

/********************* Macro Constant Definition **********************/
// #define BL_TBL_SIZE 8
#define COL_SIZE 3
#define BC_TBL_SIZE 512
#define BIT_SIZE 2
#define CELL_SIZE 4

/********************* Hash Functions Definition **********************/
field_list bl_hash_fields_1 {
    user.dst_byte_1;    
}
field_list_calculation bl_hash_fields_1_calc {
    input { 
        bl_hash_fields_1; 
    }
    algorithm: crc_8;
    output_width: 1;
}

field_list bl_hash_fields_2 {
    user.dst_byte_2;
}
field_list_calculation bl_hash_fields_2_calc {
    input { 
        bl_hash_fields_2; 
    }
    algorithm: crc_8_darc;
    output_width: 1;
}

field_list bl_hash_fields_3 {
    user.dst_byte_3;
}
field_list_calculation bl_hash_fields_3_calc {
    input { 
        bl_hash_fields_3; 
    }
    algorithm: crc_8_i_code;
    output_width: 1;
}

field_list cell1_index_hash_fields {
    ipv4.srcAddr;
}
field_list_calculation cell1_index_hash_fields_cal {
    input {
        cell1_index_hash_fields;
    }
    algorithm: crc_8_itu;
    output_width: 2;
}

field_list cell2_index_hash_fields {
    ipv4.srcAddr;
}
field_list_calculation cell2_index_hash_fields_cal {
    input {
        cell2_index_hash_fields;
    }
    algorithm: crc_8_maxim;
    output_width: 2;
}



/*********************   Registers Definition   **********************/
// BL Definition. Because of the masking and clearing options, the BL array within each cell is directly represented by a single variable
register reg_bl_r1 {
    width: 8;
    instance_count: COL_SIZE;
}

register reg_bl_r2 {
    width: 8;
    instance_count: COL_SIZE;
}

// BC Definition
register reg_bc_r1_c1 {
    width: 1;
    instance_count: BC_TBL_SIZE;
}
register reg_bc_r1_c2 {
    width: 1;
    instance_count: BC_TBL_SIZE;
}
register reg_bc_r1_c3 {
    width: 1;
    instance_count: BC_TBL_SIZE;
}
register reg_bc_r2_c1 {
    width: 1;
    instance_count: BC_TBL_SIZE;
}
register reg_bc_r2_c2 {
    width: 1;
    instance_count: BC_TBL_SIZE;
}
register reg_bc_r2_c3 {
    width: 1;
    instance_count: BC_TBL_SIZE;
}

/*********************  Register Action Definition ****************/
blackbox stateful_alu act_read_update_bl_r1 {
    reg: reg_bl_r1;

    condition_lo: mdata.resubmit == 0;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value:     register_lo;
    update_lo_2_predicate: not condition_lo;
    update_lo_2_value:     user.dst_byte_1;
}

/*********************  Actions Definition   **********************/
action act_get_bl_hash_res1() {
    modify_field_with_hash_based_offset(mdata2.bl_hash_res1, 0, bl_hash_fields_1_calc, BIT_SIZE);
}

action act_get_bl_hash_res2() {
    modify_field_with_hash_based_offset(mdata2.bl_hash_res2, 0, bl_hash_fields_2_calc, BIT_SIZE);
} 

action act_get_bl_hash_res3() {
    modify_field_with_hash_based_offset(mdata2.bl_hash_res3, 0, bl_hash_fields_3_calc, BIT_SIZE);
}

action act_get_cell1_index() {
    modify_field_with_hash_based_offset(mdata2.cell1_index, 0, cell1_index_hash_fields_cal, CELL_SIZE);
}

action act_get_cell2_index() {
    modify_field_with_hash_based_offset(mdata2.cell2_index, 0, cell2_index_hash_fields_cal, CELL_SIZE);
}

action act_get_mask1(mask1) {
    modify_field(mdata2.mask1, mask1);
}

action act_get_mask2(mask2) {
    modify_field(mdata2.mask2, mask2);
}

action act_get_mask3(mask3) {
    modify_field(mdata2.mask3, mask3);
}

/*********************   Tables Definition   **********************/
@pragma stage 0
table tbl_get_bl_hash_res1 {
    actions {
        act_get_bl_hash_res1;
    }
    default_action: act_get_bl_hash_res1();
}

@pragma stage 0
table tbl_get_bl_hash_res2 {
    actions {
        act_get_bl_hash_res2;
    }
    default_action: act_get_bl_hash_res2();
}

@pragma stage 0
table tbl_get_bl_hash_res3 {
    actions {
        act_get_bl_hash_res3;
    }
    default_action: act_get_bl_hash_res3();
}

@pragma stage 0
table tbl_get_cell1_index {
    actions {
        act_get_cell1_index;
    }
    default_action: act_get_cell1_index();
}

@pragma stage 0
table tbl_get_cell2_index {
    actions {
        act_get_cell2_index;
    }
    default_action: act_get_cell2_index();
}

// 0,1共2个表项
@pragma stage 1
table tbl_get_mask1 {
    reads {
        mdata2.bl_hash_res1: exact;
    }
    actions {
        act_get_mask1;
    }
    size: 2;
}

// 00,01,10,11共4个表项
@pragma stage 1
table tbl_get_mask2 {
    reads {
        mdata2.bl_hash_res1: exact;
        mdata2.bl_hash_res2: exact;
    }
    actions {
        act_get_mask2;
    }
    size: 4;
}

// 000,001,010,011,...,110,111共8个表项
@pragma stage 2
table tbl_get_mask3 {
    reads {
        mdata2.bl_hash_res1: exact;
        mdata2.bl_hash_res2: exact;
        mdata2.bl_hash_res3: exact;
    }
    actions {
        act_get_mask3;
    }
    size: 8;
}
// Define ingress control block
control ingress {
    // Apply hash calculations and source IP handling
   if(valid(ipv4)){
		apply(forward_ipv4);
	}       
    apply(tbl_get_cell1_index);
    apply(tbl_get_cell2_index);
    apply(tb_set_new_flag);
    apply(get_ip_table);
    apply(tbl_get_bl_hash_res1);
    apply(tbl_get_bl_hash_res2);
    apply(tbl_get_bl_hash_res3);
    if(mdata.is_new_pkt==1){

    apply(check_src_ip_hash_table);
if(mdata.src_addr!=1){

   
    apply(tbl_get_mask1);
    apply(tbl_get_mask2);
    apply(tbl_get_mask3);
    if(mdata2.bl_hash_res3!=0){
    //apply(check_depth_and_boundary_table);
  apply(tb_do_update_topk_array);
    apply(cardinality_check_table);
    apply(array_1_table);
     apply(array_1_data_table);
}
}
     }
  if (mdata.cardinality <200 )
  //if( mdata.depth != 0)
  if(mdata2.bl_hash_res3 != 7) 
  {
    apply(forward_nop);
    } else {
    apply(forward_nop);
}

}

// Define egress control block
control egress {
  //  apply(drop_packet);
}

 