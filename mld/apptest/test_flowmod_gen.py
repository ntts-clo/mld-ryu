# coding: utf-8

import sys
import unittest

from ryu.lib.packet import icmpv6
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.ofproto.ofproto_v1_3_parser import OFPActionPopVlan, OFPActionPushPbb, \
    OFPActionSetField, OFPActionPushVlan, OFPActionPopPbb

from mld.app.flowmod_gen import flow_mod_generator, apresia_12k, apresia_26k, flow_mod_gen_exception, \
    PRIORITY_NORMAL, PRIORITY_LOW
from networkx.classes.function import set_edge_attributes
sys.path.append('../../common')
from zmq_dispatch import flow_mod_data

class test_flow_mod_genrator(unittest.TestCase):


    def setUp(self):
        self.fmg = None


    def tearDown(self):
        self.fmg = None

    def test_init_001(self):

        switch_infos = []

        try:
            self.fmg = flow_mod_generator(switch_infos)
        except flow_mod_gen_exception as e:
            self.assertEquals(e.value, 'edge switch is not defined.')
            return

        raise Exception()

    def test_init_002(self):

        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12001,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        }]

        try:
            self.fmg = flow_mod_generator(switch_infos)
        except flow_mod_gen_exception as e:
            self.assertEquals(e.value, 'Unsupported sw_type:12001, datapathid=1')
            return

        raise Exception()

    def test_init_003(self):

        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12000,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        }]

        try:
            self.fmg = flow_mod_generator(switch_infos)
        except flow_mod_gen_exception as e:
            self.assertEquals(e.value, 'container switch is not defined.')
            return

        raise Exception()

    def test_init_004(self):

        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12000,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
        {
            "sw_name"   : "sw1",
            "sw_type"   : 12000,
            "datapathid": 2,
            "sw_bmac"   : "00:00:00:00:00:02",
            "edge_switch_port" : 50,
            "olt_ports" : [1]
        },
        {
            "sw_name"   : "sw2",
            "sw_type"   : 26000,
            "datapathid": 3,
            "sw_bmac"   : "00:00:00:00:00:03",
            "edge_switch_port" : 50,
            "olt_ports" : [1]
        }]

        self.fmg = flow_mod_generator(switch_infos)

        self.assertIsNotNone(self.fmg.edge_switch)
        self.assertIsInstance(self.fmg.edge_switch, apresia_12k)
        self.assertEquals(len(self.fmg.container_switches), 2)
        c_sw2 = self.fmg.container_switches[2]
        self.assertIsInstance(c_sw2, apresia_12k)
        c_sw3 = self.fmg.container_switches[3]
        self.assertIsInstance(c_sw3, apresia_26k)

    '''
    エッジSW(Apresia12000)の初期可処理
    '''
    def test_initialize_flows_001(self):

        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12000,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
        {
            "sw_name"   : "sw1",
            "sw_type"   : 12000,
            "datapathid": 2,
            "sw_bmac"   : "00:00:00:00:00:02",
            "edge_switch_port" : 50,
            "olt_ports" : [1,2]
        },
        {
            "sw_name"   : "sw2",
            "sw_type"   : 12000,
            "datapathid": 3,
            "sw_bmac"   : "00:00:00:00:00:03",
            "edge_switch_port" : 50,
            "olt_ports" : [1]
        }]

        datapathid = 1
        ivid = 2001
        pbb_isid = 10001
        bvid = 4001

        self.mfg = flow_mod_generator(switch_infos)\
            .initialize_flows(datapathid, ivid, pbb_isid, bvid)

        self.assertEquals(len(self.mfg), 5)

        # table 0
        self.assertEquals(self.mfg[0].datapathid, datapathid)
        self.assertEquals(self.mfg[0].table_id, 0)
        self.assertEquals(self.mfg[0].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[0].match['in_port'], 2)
        self.assertEquals(self.mfg[0].match['eth_type'], ether.ETH_TYPE_IPV6)
        self.assertEquals(self.mfg[0].match['ip_proto'], inet.IPPROTO_ICMPV6)
        self.assertEquals(self.mfg[0].match['icmpv6_type'], icmpv6.MLD_LISTENER_QUERY)
        self.assertEquals(len(self.mfg[0].instructions), 1)
        self.assertEquals(self.mfg[0].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[0].instructions[0].actions), 1)
        self.assertEquals(self.mfg[0].instructions[0].actions[0].port, ofproto.OFPP_CONTROLLER)
        self.assertEquals(self.mfg[0].instructions[0].actions[0].max_len, ofproto.OFPCML_NO_BUFFER)

        # table 0
        self.assertEquals(self.mfg[1].datapathid, datapathid)
        self.assertEquals(self.mfg[1].table_id, 0)
        self.assertEquals(self.mfg[1].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[1].match['in_port'], 1)
        self.assertEquals(self.mfg[1].match['eth_type'], ether.ETH_TYPE_IPV6)
        self.assertEquals(self.mfg[1].match['ip_proto'], inet.IPPROTO_ICMPV6)
        self.assertEquals(self.mfg[1].match['icmpv6_type'], icmpv6.MLDV2_LISTENER_REPORT)
        self.assertEquals(len(self.mfg[1].instructions), 1)
        self.assertEquals(self.mfg[1].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[1].instructions[0].actions), 1)
        self.assertEquals(self.mfg[1].instructions[0].actions[0].port, 2)

        # table 3
        self.assertEquals(self.mfg[2].datapathid, datapathid)
        self.assertEquals(self.mfg[2].table_id, 3)
        self.assertEquals(self.mfg[2].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[2].match['in_port'], apresia_12k.TAG2PBB)
        self.assertEquals(self.mfg[2].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[2].instructions), 1)
        self.assertEquals(self.mfg[2].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[2].instructions[0].actions), 8)
        self.assertEquals(self.mfg[2].instructions[0].actions[0].type, OFPActionPopVlan().type)
        self.assertEquals(self.mfg[2].instructions[0].actions[0].len, OFPActionPopVlan().len)
        self.assertEquals(self.mfg[2].instructions[0].actions[1].ethertype, ether.ETH_TYPE_8021AH)
        self.assertEquals(self.mfg[2].instructions[0].actions[2].key, 'pbb_isid')
        self.assertEquals(self.mfg[2].instructions[0].actions[2].value, pbb_isid)
        self.assertEquals(self.mfg[2].instructions[0].actions[3].key, 'eth_dst')
        self.assertEquals(self.mfg[2].instructions[0].actions[3].value, '00:00:00:00:00:00')
        self.assertEquals(self.mfg[2].instructions[0].actions[4].key, 'eth_src')
        self.assertEquals(self.mfg[2].instructions[0].actions[4].value, "00:00:00:00:00:01")
        self.assertEquals(self.mfg[2].instructions[0].actions[5].ethertype, ether.ETH_TYPE_8021AD)
        self.assertEquals(self.mfg[2].instructions[0].actions[6].key, 'vlan_vid')
        self.assertEquals(self.mfg[2].instructions[0].actions[6].value, bvid)
        self.assertEquals(self.mfg[2].instructions[0].actions[7].port, ofproto.OFPP_NORMAL)

        # table 4
        self.assertEquals(self.mfg[3].datapathid, datapathid)
        self.assertEquals(self.mfg[3].table_id, 4)
        self.assertEquals(self.mfg[3].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[3].match['in_port'], 0x02000000 | 50)
        self.assertEquals(self.mfg[3].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[3].instructions), 1)
        self.assertEquals(self.mfg[3].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[3].instructions[0].actions), 1)
        self.assertEquals(self.mfg[3].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 5
        self.assertEquals(self.mfg[4].datapathid, datapathid)
        self.assertEquals(self.mfg[4].table_id, 4)
        self.assertEquals(self.mfg[4].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[4].match['in_port'], 0x02000000 | 49)
        self.assertEquals(self.mfg[4].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[4].instructions), 1)
        self.assertEquals(self.mfg[4].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[4].instructions[0].actions), 1)
        self.assertEquals(self.mfg[4].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    '''
    収容SW1(Apresia12000)の初期可処理
    '''
    def test_initialize_flows_002(self):

        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12000,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
        {
            "sw_name"   : "sw1",
            "sw_type"   : 12000,
            "datapathid": 2,
            "sw_bmac"   : "00:00:00:00:00:02",
            "edge_switch_port" : 50,
            "olt_ports" : [1,2]
        },
        {
            "sw_name"   : "sw2",
            "sw_type"   : 12000,
            "datapathid": 3,
            "sw_bmac"   : "00:00:00:00:00:03",
            "edge_switch_port" : 50,
            "olt_ports" : [1]
        }]

        datapathid = 2
        ivid = 2001
        pbb_isid = 10001
        bvid = 4001

        self.mfg = flow_mod_generator(switch_infos)\
            .initialize_flows(datapathid, ivid, pbb_isid, bvid)

        self.assertEquals(len(self.mfg), 5)

        # table 0
        self.assertEquals(self.mfg[0].datapathid, datapathid)
        self.assertEquals(self.mfg[0].table_id, 0)
        self.assertEquals(self.mfg[0].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[0].match['eth_type'], ether.ETH_TYPE_IPV6)
        self.assertEquals(self.mfg[0].match['ip_proto'], inet.IPPROTO_ICMPV6)
        self.assertEquals(self.mfg[0].match['icmpv6_type'], icmpv6.MLDV2_LISTENER_REPORT)
        self.assertEquals(len(self.mfg[0].instructions), 1)
        self.assertEquals(self.mfg[0].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[0].instructions[0].actions), 1)
        self.assertEquals(self.mfg[0].instructions[0].actions[0].port, ofproto.OFPP_CONTROLLER)
        self.assertEquals(self.mfg[0].instructions[0].actions[0].max_len, ofproto.OFPCML_NO_BUFFER)

        # table 4
        self.assertEquals(self.mfg[1].datapathid, datapathid)
        self.assertEquals(self.mfg[1].table_id, 4)
        self.assertEquals(self.mfg[1].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[1].match['in_port'], 0x02000000 | 50)
        self.assertEquals(self.mfg[1].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[1].instructions), 1)
        self.assertEquals(self.mfg[1].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[1].instructions[0].actions), 1)
        self.assertEquals(self.mfg[1].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 3
        self.assertEquals(self.mfg[2].datapathid, datapathid)
        self.assertEquals(self.mfg[2].table_id, 3)
        self.assertEquals(self.mfg[2].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[2].match['in_port'], apresia_12k.PBB2TAG)
        self.assertEquals(self.mfg[2].match['eth_type'], ether.ETH_TYPE_8021AH)
        self.assertEquals(self.mfg[2].match['pbb_isid'], pbb_isid)
        self.assertEquals(self.mfg[2].match['eth_dst'], "00:00:00:00:00:02")
        self.assertEquals(len(self.mfg[2].instructions), 1)
        self.assertEquals(self.mfg[2].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[2].instructions[0].actions), 5)
        self.assertEquals(self.mfg[2].instructions[0].actions[0].type, OFPActionPopVlan().type)
        self.assertEquals(self.mfg[2].instructions[0].actions[0].len, OFPActionPopVlan().len)
        self.assertEquals(self.mfg[2].instructions[0].actions[1].type, OFPActionPopPbb().type)
        self.assertEquals(self.mfg[2].instructions[0].actions[1].len, OFPActionPopPbb().len)
        self.assertEquals(self.mfg[2].instructions[0].actions[2].ethertype, ether.ETH_TYPE_8021Q)
        self.assertEquals(self.mfg[2].instructions[0].actions[3].key, 'vlan_vid')
        self.assertEquals(self.mfg[2].instructions[0].actions[3].value, ivid)
        self.assertEquals(self.mfg[2].instructions[0].actions[4].port, ofproto.OFPP_NORMAL)

        # table 4
        self.assertEquals(self.mfg[3].datapathid, datapathid)
        self.assertEquals(self.mfg[3].table_id, 4)
        self.assertEquals(self.mfg[3].priority, PRIORITY_LOW)
        self.assertEquals(self.mfg[3].match['in_port'], 0x00000000 | 1)
        self.assertEquals(self.mfg[3].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[3].instructions), 1)
        self.assertEquals(self.mfg[3].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[3].instructions[0].actions), 1)
        self.assertEquals(self.mfg[3].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 4
        self.assertEquals(self.mfg[4].datapathid, datapathid)
        self.assertEquals(self.mfg[4].table_id, 4)
        self.assertEquals(self.mfg[4].priority, PRIORITY_LOW)
        self.assertEquals(self.mfg[4].match['in_port'], 0x00000000 | 2)
        self.assertEquals(self.mfg[4].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[4].instructions), 1)
        self.assertEquals(self.mfg[4].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[4].instructions[0].actions), 1)
        self.assertEquals(self.mfg[4].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    '''
    収容SW2(Apresia12000)の初期可処理
    '''
    def test_initialize_flows_003(self):

        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12000,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
        {
            "sw_name"   : "sw1",
            "sw_type"   : 12000,
            "datapathid": 2,
            "sw_bmac"   : "00:00:00:00:00:02",
            "edge_switch_port" : 50,
            "olt_ports" : [1,2]
        },
        {
            "sw_name"   : "sw2",
            "sw_type"   : 12000,
            "datapathid": 3,
            "sw_bmac"   : "00:00:00:00:00:03",
            "edge_switch_port" : 50,
            "olt_ports" : [1]
        }]

        datapathid = 3
        ivid = 2001
        pbb_isid = 10001
        bvid = 4001

        self.mfg = flow_mod_generator(switch_infos)\
            .initialize_flows(datapathid, ivid, pbb_isid, bvid)

        self.assertEquals(len(self.mfg), 4)

        # table 0
        self.assertEquals(self.mfg[0].datapathid, datapathid)
        self.assertEquals(self.mfg[0].table_id, 0)
        self.assertEquals(self.mfg[0].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[0].match['eth_type'], ether.ETH_TYPE_IPV6)
        self.assertEquals(self.mfg[0].match['ip_proto'], inet.IPPROTO_ICMPV6)
        self.assertEquals(self.mfg[0].match['icmpv6_type'], icmpv6.MLDV2_LISTENER_REPORT)
        self.assertEquals(len(self.mfg[0].instructions), 1)
        self.assertEquals(self.mfg[0].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[0].instructions[0].actions), 1)
        self.assertEquals(self.mfg[0].instructions[0].actions[0].port, ofproto.OFPP_CONTROLLER)
        self.assertEquals(self.mfg[0].instructions[0].actions[0].max_len, ofproto.OFPCML_NO_BUFFER)

        # table 4
        self.assertEquals(self.mfg[1].datapathid, datapathid)
        self.assertEquals(self.mfg[1].table_id, 4)
        self.assertEquals(self.mfg[1].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[1].match['in_port'], 0x02000000 | 50)
        self.assertEquals(self.mfg[1].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[1].instructions), 1)
        self.assertEquals(self.mfg[1].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[1].instructions[0].actions), 1)
        self.assertEquals(self.mfg[1].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        #table 3
        self.assertEquals(self.mfg[2].datapathid, datapathid)
        self.assertEquals(self.mfg[2].table_id, 3)
        self.assertEquals(self.mfg[2].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[2].match['in_port'], apresia_12k.PBB2TAG)
        self.assertEquals(self.mfg[2].match['eth_type'], ether.ETH_TYPE_8021AH)
        self.assertEquals(self.mfg[2].match['pbb_isid'], pbb_isid)
        self.assertEquals(self.mfg[2].match['eth_dst'], "00:00:00:00:00:03")
        self.assertEquals(len(self.mfg[2].instructions), 1)
        self.assertEquals(self.mfg[2].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[2].instructions[0].actions), 5)
        self.assertEquals(self.mfg[2].instructions[0].actions[0].type, OFPActionPopVlan().type)
        self.assertEquals(self.mfg[2].instructions[0].actions[0].len, OFPActionPopVlan().len)
        self.assertEquals(self.mfg[2].instructions[0].actions[1].type, OFPActionPopPbb().type)
        self.assertEquals(self.mfg[2].instructions[0].actions[1].len, OFPActionPopPbb().len)
        self.assertEquals(self.mfg[2].instructions[0].actions[2].ethertype, ether.ETH_TYPE_8021Q)
        self.assertEquals(self.mfg[2].instructions[0].actions[3].key, 'vlan_vid')
        self.assertEquals(self.mfg[2].instructions[0].actions[3].value, ivid)
        self.assertEquals(self.mfg[2].instructions[0].actions[4].port, ofproto.OFPP_NORMAL)

        # table 4
        self.assertEquals(self.mfg[3].datapathid, datapathid)
        self.assertEquals(self.mfg[3].table_id, 4)
        self.assertEquals(self.mfg[3].priority, PRIORITY_LOW)
        self.assertEquals(self.mfg[3].match['in_port'], 0x00000000 | 1)
        self.assertEquals(self.mfg[3].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[3].instructions), 1)
        self.assertEquals(self.mfg[3].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[3].instructions[0].actions), 1)
        self.assertEquals(self.mfg[3].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)


    '''
    datapath 2 視聴開始(初回ユーザ参加)
    '''
    def test_start_mg_001(self):

        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12000,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
        {
            "sw_name"   : "sw1",
            "sw_type"   : 12000,
            "datapathid": 2,
            "sw_bmac"   : "00:00:00:00:00:02",
            "edge_switch_port" : 50,
            "olt_ports" : [1,2]
        },
        {
            "sw_name"   : "sw2",
            "sw_type"   : 12000,
            "datapathid": 3,
            "sw_bmac"   : "00:00:00:00:00:03",
            "edge_switch_port" : 50,
            "olt_ports" : [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 1
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        edge_sw_bmac = switch_infos[0]['sw_bmac']
        container_sw_bmac = switch_infos[1]['sw_bmac']

        self.fmg = flow_mod_generator(switch_infos)\
            .start_mg(multicast_address, datapathid, portno, ivid, pbb_isid, bvid)

        # エッジSWのFlowModが3つ、収容SWのFlowModが3つ配列に格納される
        self.assertEquals(len(self.fmg), 6)

        # 以下、エッジSWのFlowMod
        # table 2
        self.assertEquals(self.fmg[0].datapathid, datapathid)
        self.assertEquals(self.fmg[0].table_id, 2)
        self.assertEquals(self.fmg[0].priority, PRIORITY_NORMAL)
        self.assertEquals(self.fmg[0].match['in_port'], 2)
        self.assertEquals(self.fmg[0].match['eth_type'], ether.ETH_TYPE_IPV6)
        self.assertEquals(self.fmg[0].match['ipv6_dst'], multicast_address)
        self.assertEquals(len(self.fmg[0].instructions), 1)
        self.assertEquals(self.fmg[0].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[0].instructions[0].actions), 2)
        self.assertEquals(self.fmg[0].instructions[0].actions[0].key, 'vlan_vid')
        self.assertEquals(self.fmg[0].instructions[0].actions[0].value, ivid)
        self.assertEquals(self.fmg[0].instructions[0].actions[1].port, ofproto.OFPP_NORMAL)

        # table 3
        self.assertEquals(self.fmg[1].datapathid, datapathid)
        self.assertEquals(self.fmg[1].table_id, 3)
        self.assertEquals(self.fmg[1].priority, PRIORITY_NORMAL)
        self.assertEquals(self.fmg[1].match['in_port'], apresia_12k.TAG2PBB)
        self.assertEquals(self.fmg[1].match['vlan_vid'], ivid)
        self.assertEquals(len(self.fmg[1].instructions), 1)
        self.assertEquals(self.fmg[1].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[1].instructions[0].actions), 8)
        self.assertEquals(self.fmg[1].instructions[0].actions[0].type, OFPActionPopVlan().type)
        self.assertEquals(self.fmg[1].instructions[0].actions[0].len, OFPActionPopVlan().len)
        self.assertEquals(self.fmg[1].instructions[0].actions[1].ethertype, ether.ETH_TYPE_8021AH)
        self.assertEquals(self.fmg[1].instructions[0].actions[2].key, 'pbb_isid')
        self.assertEquals(self.fmg[1].instructions[0].actions[2].value, pbb_isid)
        self.assertEquals(self.fmg[1].instructions[0].actions[3].key, 'eth_dst')
        self.assertEquals(self.fmg[1].instructions[0].actions[3].value, '00:00:00:00:00:00')
        self.assertEquals(self.fmg[1].instructions[0].actions[4].key, 'eth_src')
        self.assertEquals(self.fmg[1].instructions[0].actions[4].value, edge_sw_bmac)
        self.assertEquals(self.fmg[1].instructions[0].actions[5].ethertype, ether.ETH_TYPE_8021AD)
        self.assertEquals(self.fmg[1].instructions[0].actions[6].key, 'vlan_vid')
        self.assertEquals(self.fmg[1].instructions[0].actions[6].value, bvid)
        self.assertEquals(self.fmg[1].instructions[0].actions[7].port, ofproto.OFPP_NORMAL)

        # table 4
        self.assertEquals(self.fmg[2].datapathid, datapathid)
        self.assertEquals(self.fmg[2].table_id, 4)
        self.assertEquals(self.fmg[2].priority, PRIORITY_NORMAL)
        self.assertEquals(self.fmg[2].match['in_port'], 0x02000000 | 49)
        self.assertEquals(self.fmg[2].match['vlan_vid'], ivid)
        self.assertEquals(len(self.fmg[2].instructions), 1)
        self.assertEquals(self.fmg[2].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[2].instructions[0].actions), 1)
        self.assertEquals(self.fmg[2].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # 以下、収容SWのFlowMod
        # table 4
        self.assertEquals(self.fmg[3].datapathid, datapathid)
        self.assertEquals(self.fmg[3].table_id, 4)
        self.assertEquals(self.fmg[3].priority, PRIORITY_NORMAL)
        self.assertEquals(self.fmg[3].match['in_port'], 0x02000000 | 50)
        self.assertEquals(self.fmg[3].match['vlan_vid'], ivid)
        self.assertEquals(len(self.fmg[3].instructions), 1)
        self.assertEquals(self.fmg[3].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[3].instructions[0].actions), 1)
        self.assertEquals(self.fmg[3].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 3
        self.assertEquals(self.fmg[4].datapathid, datapathid)
        self.assertEquals(self.fmg[4].table_id, 3)
        self.assertEquals(self.fmg[4].priority, PRIORITY_NORMAL)
        self.assertEquals(self.fmg[4].match['in_port'], apresia_12k.PBB2TAG)
        # PBBデカプセル時のBVIDは省略可
        self.assertEquals(self.fmg[4].match['eth_type'], ether.ETH_TYPE_8021AH)
        self.assertEquals(self.fmg[4].match['pbb_isid'], pbb_isid)
        self.assertEquals(self.fmg[4].match['eth_dst'], container_sw_bmac)
        self.assertEquals(len(self.fmg[4].instructions), 1)
        self.assertEquals(self.fmg[4].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[4].instructions[0].actions), 5)
        self.assertEquals(self.fmg[4].instructions[0].actions[0].type, OFPActionPopVlan().type)
        self.assertEquals(self.fmg[4].instructions[0].actions[0].len, OFPActionPopVlan().len)
        self.assertEquals(self.fmg[4].instructions[0].actions[1].type, OFPActionPopPbb().type)
        self.assertEquals(self.fmg[4].instructions[0].actions[1].len, OFPActionPopPbb().len)
        self.assertEquals(self.fmg[4].instructions[0].actions[2].ethertype, ether.ETH_TYPE_8021Q)
        self.assertEquals(self.fmg[4].instructions[0].actions[3].key, 'vlan_vid')
        self.assertEquals(self.fmg[4].instructions[0].actions[3].value, ivid)
        self.assertEquals(self.fmg[4].instructions[0].actions[4].port, ofproto.OFPP_NORMAL)

        # table 4
        self.assertEquals(self.fmg[5].datapathid, datapathid)
        self.assertEquals(self.fmg[5].table_id, 4)
        self.assertEquals(self.fmg[5].priority, PRIORITY_LOW)
        self.assertEquals(self.fmg[5].match['in_port'], 0x00000000 | portno)
        self.assertEquals(self.fmg[5].match['vlan_vid'], ivid)
        self.assertEquals(len(self.fmg[5].instructions), 1)
        self.assertEquals(self.fmg[5].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[5].instructions[0].actions), 1)
        self.assertEquals(self.fmg[5].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)


    '''
    datapath 3 視聴開始(初回ユーザ参加)
    '''
    def test_start_mg_002(self):

        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12000,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
        {
            "sw_name"   : "sw1",
            "sw_type"   : 12000,
            "datapathid": 2,
            "sw_bmac"   : "00:00:00:00:00:02",
            "edge_switch_port" : 50,
            "olt_ports" : [1,2]
        },
        {
            "sw_name"   : "sw2",
            "sw_type"   : 12000,
            "datapathid": 3,
            "sw_bmac"   : "00:00:00:00:00:03",
            "edge_switch_port" : 50,
            "olt_ports" : [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 3
        portno = 1
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        edge_sw_bmac = switch_infos[0]['sw_bmac']
        container_sw_bmac = switch_infos[2]['sw_bmac']

        self.fmg = flow_mod_generator(switch_infos)\
            .start_mg(multicast_address, datapathid, portno, ivid, pbb_isid, bvid)

        # エッジSWのFlowModが3つ、収容SWのFlowModが3つ配列に格納される
        self.assertEquals(len(self.fmg), 6)

        # 以下、エッジSWのFlowMod
        # table 2
        self.assertEquals(self.fmg[0].datapathid, datapathid)
        self.assertEquals(self.fmg[0].table_id, 2)
        self.assertEquals(self.fmg[0].priority, PRIORITY_NORMAL)
        self.assertEquals(self.fmg[0].match['in_port'], 2)
        self.assertEquals(self.fmg[0].match['eth_type'], ether.ETH_TYPE_IPV6)
        self.assertEquals(self.fmg[0].match['ipv6_dst'], multicast_address)
        self.assertEquals(len(self.fmg[0].instructions), 1)
        self.assertEquals(self.fmg[0].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[0].instructions[0].actions), 2)
        self.assertEquals(self.fmg[0].instructions[0].actions[0].key, 'vlan_vid')
        self.assertEquals(self.fmg[0].instructions[0].actions[0].value, ivid)
        self.assertEquals(self.fmg[0].instructions[0].actions[1].port, ofproto.OFPP_NORMAL)

        # table 3
        self.assertEquals(self.fmg[1].datapathid, datapathid)
        self.assertEquals(self.fmg[1].table_id, 3)
        self.assertEquals(self.fmg[1].priority, PRIORITY_NORMAL)
        self.assertEquals(self.fmg[1].match['in_port'], apresia_12k.TAG2PBB)
        self.assertEquals(self.fmg[1].match['vlan_vid'], ivid)
        self.assertEquals(len(self.fmg[1].instructions), 1)
        self.assertEquals(self.fmg[1].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[1].instructions[0].actions), 8)
        self.assertEquals(self.fmg[1].instructions[0].actions[0].type, OFPActionPopVlan().type)
        self.assertEquals(self.fmg[1].instructions[0].actions[0].len, OFPActionPopVlan().len)
        self.assertEquals(self.fmg[1].instructions[0].actions[1].ethertype, ether.ETH_TYPE_8021AH)
        self.assertEquals(self.fmg[1].instructions[0].actions[2].key, 'pbb_isid')
        self.assertEquals(self.fmg[1].instructions[0].actions[2].value, pbb_isid)
        self.assertEquals(self.fmg[1].instructions[0].actions[3].key, 'eth_dst')
        self.assertEquals(self.fmg[1].instructions[0].actions[3].value, '00:00:00:00:00:00')
        self.assertEquals(self.fmg[1].instructions[0].actions[4].key, 'eth_src')
        self.assertEquals(self.fmg[1].instructions[0].actions[4].value, edge_sw_bmac)
        self.assertEquals(self.fmg[1].instructions[0].actions[5].ethertype, ether.ETH_TYPE_8021AD)
        self.assertEquals(self.fmg[1].instructions[0].actions[6].key, 'vlan_vid')
        self.assertEquals(self.fmg[1].instructions[0].actions[6].value, bvid)
        self.assertEquals(self.fmg[1].instructions[0].actions[7].port, ofproto.OFPP_NORMAL)

        # table 4
        self.assertEquals(self.fmg[2].datapathid, datapathid)
        self.assertEquals(self.fmg[2].table_id, 4)
        self.assertEquals(self.fmg[2].priority, PRIORITY_NORMAL)
        self.assertEquals(self.fmg[2].match['in_port'], 0x02000000 | 50)
        self.assertEquals(self.fmg[2].match['vlan_vid'], ivid)
        self.assertEquals(len(self.fmg[2].instructions), 1)
        self.assertEquals(self.fmg[2].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[2].instructions[0].actions), 1)
        self.assertEquals(self.fmg[2].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # 以下、収容SWのFlowMod
        # table 4
        self.assertEquals(self.fmg[3].datapathid, datapathid)
        self.assertEquals(self.fmg[3].table_id, 4)
        self.assertEquals(self.fmg[3].priority, PRIORITY_NORMAL)
        self.assertEquals(self.fmg[3].match['in_port'], 0x02000000 | 50)
        self.assertEquals(self.fmg[3].match['vlan_vid'], ivid)
        self.assertEquals(len(self.fmg[3].instructions), 1)
        self.assertEquals(self.fmg[3].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[3].instructions[0].actions), 1)
        self.assertEquals(self.fmg[3].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 3
        self.assertEquals(self.fmg[4].datapathid, datapathid)
        self.assertEquals(self.fmg[4].table_id, 3)
        self.assertEquals(self.fmg[4].priority, PRIORITY_NORMAL)
        self.assertEquals(self.fmg[4].match['in_port'], apresia_12k.PBB2TAG)
        # PBBデカプセル時のBVIDは省略可
        self.assertEquals(self.fmg[4].match['eth_type'], ether.ETH_TYPE_8021AH)
        self.assertEquals(self.fmg[4].match['pbb_isid'], pbb_isid)
        self.assertEquals(self.fmg[4].match['eth_dst'], container_sw_bmac)
        self.assertEquals(len(self.fmg[4].instructions), 1)
        self.assertEquals(self.fmg[4].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[4].instructions[0].actions), 5)
        self.assertEquals(self.fmg[4].instructions[0].actions[0].type, OFPActionPopVlan().type)
        self.assertEquals(self.fmg[4].instructions[0].actions[0].len, OFPActionPopVlan().len)
        self.assertEquals(self.fmg[4].instructions[0].actions[1].type, OFPActionPopPbb().type)
        self.assertEquals(self.fmg[4].instructions[0].actions[1].len, OFPActionPopPbb().len)
        self.assertEquals(self.fmg[4].instructions[0].actions[2].ethertype, ether.ETH_TYPE_8021Q)
        self.assertEquals(self.fmg[4].instructions[0].actions[3].key, 'vlan_vid')
        self.assertEquals(self.fmg[4].instructions[0].actions[3].value, ivid)
        self.assertEquals(self.fmg[4].instructions[0].actions[4].port, ofproto.OFPP_NORMAL)

        # table 4
        self.assertEquals(self.fmg[5].datapathid, datapathid)
        self.assertEquals(self.fmg[5].table_id, 4)
        self.assertEquals(self.fmg[5].priority, PRIORITY_LOW)
        self.assertEquals(self.fmg[5].match['in_port'], 0x00000000 | portno)
        self.assertEquals(self.fmg[5].match['vlan_vid'], ivid)
        self.assertEquals(len(self.fmg[5].instructions), 1)
        self.assertEquals(self.fmg[5].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.fmg[5].instructions[0].actions), 1)
        self.assertEquals(self.fmg[5].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)


    '''
    SW1にport2を追加
    '''
    def test_add_port_001(self):
         
        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12000,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
        {
            "sw_name"   : "sw1",
            "sw_type"   : 12000,
            "datapathid": 2,
            "sw_bmac"   : "00:00:00:00:00:02",
            "edge_switch_port" : 50,
            "olt_ports" : [1,2,3]
        },
        {
            "sw_name"   : "sw2",
            "sw_type"   : 12000,
            "datapathid": 3,
            "sw_bmac"   : "00:00:00:00:00:03",
            "edge_switch_port" : 50,
            "olt_ports" : [1]
        }]
 
        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        self.mfg = flow_mod_generator(switch_infos)\
            .add_port(multicast_address, datapathid, portno, ivid, pbb_isid, bvid)

        self.assertEquals(len(self.mfg), 1)
        
        # table 4
        self.assertEquals(self.mfg[0].datapathid, datapathid)
        self.assertEquals(self.mfg[0].table_id, 4)
        self.assertEquals(self.mfg[0].priority, PRIORITY_LOW)
        self.assertEquals(self.mfg[0].match['in_port'], portno)
        self.assertEquals(self.mfg[0].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[0].instructions), 1)
        self.assertEquals(self.mfg[0].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[0].instructions[0].actions), 1)
        self.assertEquals(self.mfg[0].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)


    '''
    SW1にport3を追加
    '''
    def test_add_port_002(self):
         
        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12000,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
        {
            "sw_name"   : "sw1",
            "sw_type"   : 12000,
            "datapathid": 2,
            "sw_bmac"   : "00:00:00:00:00:02",
            "edge_switch_port" : 50,
            "olt_ports" : [1,2,3]
        },
        {
            "sw_name"   : "sw2",
            "sw_type"   : 12000,
            "datapathid": 3,
            "sw_bmac"   : "00:00:00:00:00:03",
            "edge_switch_port" : 50,
            "olt_ports" : [1]
        }]
 
        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 3
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        self.mfg = flow_mod_generator(switch_infos)\
            .add_port(multicast_address, datapathid, portno, ivid, pbb_isid, bvid)

        self.assertEquals(len(self.mfg), 1)
        
        # table 4
        self.assertEquals(self.mfg[0].datapathid, datapathid)
        self.assertEquals(self.mfg[0].table_id, 4)
        self.assertEquals(self.mfg[0].priority, PRIORITY_LOW)
        self.assertEquals(self.mfg[0].match['in_port'], portno)
        self.assertEquals(self.mfg[0].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[0].instructions), 1)
        self.assertEquals(self.mfg[0].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[0].instructions[0].actions), 1)
        self.assertEquals(self.mfg[0].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)


    '''
    SW1,port2を追加
    '''
    def test_add_datapath_001(self):
         
        switch_infos = [{
            "sw_name"   : "esw",
            "sw_type"   : 12000,
            "datapathid": 1,
            "sw_bmac"   : "00:00:00:00:00:01",
            "edge_router_port" :  2,
            "mld_port"  : 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
        {
            "sw_name"   : "sw1",
            "sw_type"   : 12000,
            "datapathid": 2,
            "sw_bmac"   : "00:00:00:00:00:02",
            "edge_switch_port" : 50,
            "olt_ports" : [1,2,3]
        },
        {
            "sw_name"   : "sw2",
            "sw_type"   : 12000,
            "datapathid": 3,
            "sw_bmac"   : "00:00:00:00:00:03",
            "edge_switch_port" : 50,
            "olt_ports" : [1]
        }]
 
        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        edge_sw_bmac = switch_infos[0]['sw_bmac']
        container_sw_bmac = switch_infos[1]['sw_bmac']

        self.mfg = flow_mod_generator(switch_infos)\
            .add_datapath(multicast_address, datapathid, portno, ivid, pbb_isid, bvid)

        self.assertEquals(len(self.mfg), 5)
        
        # 以下、エッジSW
        # table 3
        self.assertEquals(self.mfg[0].datapathid, datapathid)
        self.assertEquals(self.mfg[0].table_id, 3)
        self.assertEquals(self.mfg[0].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[0].match['in_port'], apresia_12k.TAG2PBB)
        self.assertEquals(self.mfg[0].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[0].instructions), 1)
        self.assertEquals(self.mfg[0].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[0].instructions[0].actions), 8)
        self.assertEquals(self.mfg[0].instructions[0].actions[0].type, OFPActionPopVlan().type)
        self.assertEquals(self.mfg[0].instructions[0].actions[0].len, OFPActionPopVlan().len)
        self.assertEquals(self.mfg[0].instructions[0].actions[1].ethertype, ether.ETH_TYPE_8021AH)
        self.assertEquals(self.mfg[0].instructions[0].actions[2].key, 'pbb_isid')
        self.assertEquals(self.mfg[0].instructions[0].actions[2].value, pbb_isid)
        self.assertEquals(self.mfg[0].instructions[0].actions[3].key, 'eth_dst')
        self.assertEquals(self.mfg[0].instructions[0].actions[3].value, '00:00:00:00:00:00')
        self.assertEquals(self.mfg[0].instructions[0].actions[4].key, 'eth_src')
        self.assertEquals(self.mfg[0].instructions[0].actions[4].value, edge_sw_bmac)
        self.assertEquals(self.mfg[0].instructions[0].actions[5].ethertype, ether.ETH_TYPE_8021AD)
        self.assertEquals(self.mfg[0].instructions[0].actions[6].key, 'vlan_vid')
        self.assertEquals(self.mfg[0].instructions[0].actions[6].value, bvid)
        self.assertEquals(self.mfg[0].instructions[0].actions[7].port, ofproto.OFPP_NORMAL)

        # table 4
        self.assertEquals(self.mfg[1].datapathid, datapathid)
        self.assertEquals(self.mfg[1].table_id, 4)
        self.assertEquals(self.mfg[1].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[1].match['in_port'], 0x02000000|49)
        self.assertEquals(self.mfg[1].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[1].instructions), 1)
        self.assertEquals(self.mfg[1].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[1].instructions[0].actions), 1)
        self.assertEquals(self.mfg[1].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # 以下、収容SW
        # table 4
        self.assertEquals(self.mfg[2].datapathid, datapathid)
        self.assertEquals(self.mfg[2].table_id, 4)
        self.assertEquals(self.mfg[2].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[2].match['in_port'], 0x02000000|50)
        self.assertEquals(self.mfg[2].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[2].instructions), 1)
        self.assertEquals(self.mfg[2].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[2].instructions[0].actions), 1)
        self.assertEquals(self.mfg[2].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 3
        self.assertEquals(self.mfg[3].datapathid, datapathid)
        self.assertEquals(self.mfg[3].table_id, 3)
        self.assertEquals(self.mfg[3].priority, PRIORITY_NORMAL)
        self.assertEquals(self.mfg[3].match['in_port'], apresia_12k.PBB2TAG)
        self.assertEquals(self.mfg[3].match['eth_type'], ether.ETH_TYPE_8021AH)
        self.assertEquals(self.mfg[3].match['pbb_isid'], pbb_isid)
        self.assertEquals(self.mfg[3].match['eth_dst'], container_sw_bmac)
        self.assertEquals(len(self.mfg[3].instructions), 1)
        self.assertEquals(self.mfg[3].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[3].instructions[0].actions), 5)
        self.assertEquals(self.mfg[3].instructions[0].actions[0].type, OFPActionPopVlan().type)
        self.assertEquals(self.mfg[3].instructions[0].actions[0].len, OFPActionPopVlan().len)
        self.assertEquals(self.mfg[3].instructions[0].actions[1].type, OFPActionPopPbb().type)
        self.assertEquals(self.mfg[3].instructions[0].actions[1].len, OFPActionPopPbb().len)
        self.assertEquals(self.mfg[3].instructions[0].actions[2].ethertype, ether.ETH_TYPE_8021Q)
        self.assertEquals(self.mfg[3].instructions[0].actions[3].key, 'vlan_vid')
        self.assertEquals(self.mfg[3].instructions[0].actions[3].value, ivid)
        self.assertEquals(self.mfg[3].instructions[0].actions[4].port, ofproto.OFPP_NORMAL)
        
        # table 4
        self.assertEquals(self.mfg[4].datapathid, datapathid)
        self.assertEquals(self.mfg[4].table_id, 4)
        self.assertEquals(self.mfg[4].priority, PRIORITY_LOW)
        self.assertEquals(self.mfg[4].match['in_port'], 0x00000000|portno)
        self.assertEquals(self.mfg[4].match['vlan_vid'], ivid)
        self.assertEquals(len(self.mfg[4].instructions), 1)
        self.assertEquals(self.mfg[4].instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        self.assertEquals(len(self.mfg[4].instructions[0].actions), 1)
        self.assertEquals(self.mfg[4].instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

if __name__ == "__main__":
    unittest.main()

