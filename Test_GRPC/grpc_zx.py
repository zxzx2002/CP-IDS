#!/usr/bin/python3
import sys
sys.path.append('/root/bf-sde-9.10.0/install/lib/python3.7/site-packages/tofino/')
sys.path.append('/root/bf-sde-9.10.0/install/lib/python3.7/site-packages/tofino/bfrt_grpc/')
import bfrt_grpc.client as gc

from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
import ptf.dataplane as dataplane

import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.bfruntime_pb2_grpc as  p4runtime_pb2_grpc
import grpc
# import sarima_LSTM.my_grpc_sarima as sarima_LSTM

# Connect to the BF Runtime Server
for bfrt_client_id in range(10):
    interface = gc.ClientInterface(
        grpc_addr = 'localhost:50052',
        client_id = bfrt_client_id,
        device_id = 0,
        num_tries = 1)
    print('Connected to BF Runtime Server as client', bfrt_client_id)
    break;

# Get the information about the running program
bfrt_info = interface.bfrt_info_get()
print('The target runs the program ', bfrt_info.p4_name_get())
# Establish that you are using this program on the given connection
if bfrt_client_id == 0:
    interface.bind_pipeline_config(bfrt_info.p4_name_get())

####################################################################
################### You can now use BFRT CLIENT ###########################
####################################################################
target = gc.Target(device_id=0, pipe_id=0xffff)

####################################################################
################### Registers  ###########################
####################################################################
def set_register_data(target,bfrt_info,table_name, field_name, index, pipe, myvalue):
    #set register_value
    register_table = bfrt_info.table_get(table_name)
    register_table.entry_add(
                target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', index)])],
                [register_table.make_data([gc.DataTuple('f1', myvalue)])]
            )
def get_register_data(target,bfrt_info,table_name, field_name, index, pipe):
    #read register_value
    register_table = bfrt_info.table_get(table_name)
    reg_value = register_table.entry_get(
                target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', index)])],
                {"from_hw": True})
    data, _ = next(reg_value)
    value = data.to_dict()[field_name][pipe]  # register has 4 pipes
    return value

index = 1
pipe = 1
myvalue = 1212
table_name = "pipe.MyIngress.bloomfilter"
field_name = 'MyIngress.bloomfilter.f1'
set_register_data(target, bfrt_info, table_name, field_name, index, pipe, myvalue)
value = get_register_data(target, bfrt_info, table_name, field_name, index, pipe)
print("reg_value = ", value)

####################################################################
################### Set CPU_Ports ###########################
####################################################################
def clearTable(target,table_name):
    my_table = bfrt_info.table_get(table_name)
    my_table.entry_del(target)

# init CPU ports and set forwarding
def set_table(target, bfrt_info,table_name,key_name, key_value, field_name, field_value, action_name):
    my_table = bfrt_info.table_get(table_name)
    my_table.entry_add(
        target,
        [my_table.make_key([gc.KeyTuple(key_name, key_value)])],#match name, compare value
        [my_table.make_data([
            gc.DataTuple(field_name, field_value)], # if hit, set value
            action_name)] # set value in this action in P4
    )

forwarding_table = 'MyIngress.forwarding'
forwarding_key = 'ig_intr_md.ingress_port'
forwarding_key_value = 160
forwarding_field_name = 'egress_port'
forwarding_field_value = 160 #CPU port
forwarding_action = 'MyIngress.set_egress_port'
clearTable(target, forwarding_table)
set_table(target, bfrt_info, forwarding_table, forwarding_key, forwarding_key_value,
          forwarding_field_name, forwarding_field_value, forwarding_action)

####################################################################
################### Listen CPU_Ports ###########################
####################################################################
from scapy.all import sniff
def handle_packet(pkt):
   pkt.show()

filter_rule ="src host=192.168.8.107"
sniff(iface="ens1", filter=filter_rule, prn=handle_packet)
