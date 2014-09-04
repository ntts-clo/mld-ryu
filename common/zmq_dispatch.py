# coding: utf-8
from ryu.ofproto import ofproto_v1_3
import mld_const as const


class dispatch():
    def __init__(self, type_, datapathid, in_port=-1, cid=0, data=None):
        self.dispatch = {}
        self.dispatch[const.DISP_TYPE] = type_
        self.dispatch[const.DISP_DPID] = datapathid
        self.dispatch[const.DISP_IN_PORT] = in_port
        self.dispatch[const.DISP_CID] = cid
        self.dispatch[const.DISP_DATA] = data

    def __getitem__(self, key):
        return self.dispatch[key]

    def __getstate__(self):
        return self.dispatch.copy()

    def __setstate__(self, data):
        self.dispatch = data


# =====================================================================
# PacketOutの転送用データクラス
# =====================================================================
class packet_out_data(object):
    def __init__(self, datapathid,
                 buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                 in_port=ofproto_v1_3.OFPP_CONTROLLER,
                 actions=[],
                 data=None):

        self.datapathid = datapathid
        self.buffer_id = buffer_id
        self.in_port = in_port
        self.actions = actions
        self.data = data


# =====================================================================
# FlowModの転送用データクラス
# =====================================================================
class flow_mod_data(object):

    def __init__(self, datapathid, table_id, priority, match, instructions=[],
                 command=ofproto_v1_3.OFPFC_ADD, out_port=0, out_group=0):

        self.datapathid = datapathid
        self.command = command
        self.out_port = out_port
        self.out_group = out_group
        self.table_id = table_id
        self.priority = priority
        self.match = match
        self.instructions = instructions
