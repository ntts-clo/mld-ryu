# coding: utf-8

import unittest
from nose.tools import ok_, eq_

from ryu.lib.packet import icmpv6
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto.ofproto_v1_3_parser import OFPActionPopVlan, OFPActionPopPbb

from mld.app.flowmod_gen import flow_mod_generator, apresia_12k, apresia_26k, flow_mod_gen_exception, \
    PRIORITY_NORMAL, PRIORITY_LOW


class test_flow_mod_genrator(object):

    def setUp(self):
        self.fmg = None

    def tearDown(self):
        self.fmg = None

    def test_init_001(self):

        switch_infos = []

        try:
            self.fmg = flow_mod_generator(switch_infos)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'edge switch is not defined.')
            return

        raise Exception()

    def test_init_002(self):

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12001,
            "datapathid": 1,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        }]

        try:
            self.fmg = flow_mod_generator(switch_infos)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'Unsupported sw_type:12001, datapathid=1')
            return

        raise Exception()

    def test_init_003(self):

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": 1,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        }]

        try:
            self.fmg = flow_mod_generator(switch_infos)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'container switch is not defined.')
            return

        raise Exception()

    def test_init_004(self):

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": 1,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1]
        },
            {
            "sw_name": "sw2",
            "sw_type": 26000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        self.fmg = flow_mod_generator(switch_infos)

        ok_(self.fmg.edge_switch is not None)
        ok_(isinstance(self.fmg.edge_switch, apresia_12k))
        eq_(len(self.fmg.container_switches), 2)
        c_sw2 = self.fmg.container_switches[2]
        ok_(isinstance(c_sw2, apresia_12k))
        c_sw3 = self.fmg.container_switches[3]
        ok_(isinstance(c_sw3, apresia_26k))

    # =========================================================================
    # エッジSW(Apresia12000)の初期可処理 1
    # =========================================================================
    def test_initialize_flows_001(self):

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": 1,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        datapathid = 1
        ivid = 2001
        pbb_isid = 10001
        bvid = 4001

        self.fmg = flow_mod_generator(switch_infos)\
            .initialize_flows(datapathid, ivid, pbb_isid, bvid)

        eq_(len(self.fmg), 4)

        # table 0
        fmd_table_0 = self.fmg[0]
        eq_(fmd_table_0.datapathid, datapathid)
        eq_(fmd_table_0.table_id, 0)
        eq_(fmd_table_0.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_0.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_0.match['in_port'], 2)
        eq_(fmd_table_0.match['eth_type'], ether.ETH_TYPE_IPV6)
        eq_(fmd_table_0.match['ip_proto'], inet.IPPROTO_ICMPV6)
        eq_(fmd_table_0.match['icmpv6_type'], icmpv6.MLD_LISTENER_QUERY)
        eq_(len(fmd_table_0.instructions), 1)
        eq_(fmd_table_0.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_0.instructions[0].actions), 1)
        eq_(fmd_table_0.instructions[0].actions[0].port,
            ofproto.OFPP_CONTROLLER)
        eq_(fmd_table_0.instructions[0].actions[0].max_len,
            ofproto.OFPCML_NO_BUFFER)

        # table 3
        fmd_table_3 = self.fmg[1]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_3.match['in_port'], apresia_12k.TAG2PBB)
        eq_(fmd_table_3.match['vlan_vid'], ivid)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 8)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].ethertype,
            ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.instructions[0].actions[2].key, 'pbb_isid')
        eq_(fmd_table_3.instructions[0].actions[2].value, pbb_isid)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'eth_dst')
        eq_(fmd_table_3.instructions[0].actions[3].value, '00:00:00:00:00:00')
        eq_(fmd_table_3.instructions[0].actions[4].key, 'eth_src')
        eq_(fmd_table_3.instructions[0].actions[4].value, "00:00:00:00:00:01")
        eq_(fmd_table_3.instructions[0].actions[5].ethertype,
            ether.ETH_TYPE_8021AD)
        eq_(fmd_table_3.instructions[0].actions[6].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[6].value, bvid)
        eq_(fmd_table_3.instructions[0].actions[7].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 50)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[3]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 49)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    # =========================================================================
    # エッジSW(Apresia12000)の初期可処理 2
    # =========================================================================
    def test_initialize_flows_002(self):

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": 4,
            "sw_bmac": "00:00:00:00:00:04",
            "edge_router_port": 3,
            "mld_port": 2,
            "container_sw_ports": {
                "2": 59,
                "3": 60
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        datapathid = 4
        ivid = 2002
        pbb_isid = 10002
        bvid = 4002

        self.fmg = flow_mod_generator(switch_infos)\
            .initialize_flows(datapathid, ivid, pbb_isid, bvid)

        eq_(len(self.fmg), 4)

        # table 0
        fmd_table_0 = self.fmg[0]
        eq_(fmd_table_0.datapathid, datapathid)
        eq_(fmd_table_0.table_id, 0)
        eq_(fmd_table_0.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_0.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_0.match['in_port'], 3)
        eq_(fmd_table_0.match['eth_type'], ether.ETH_TYPE_IPV6)
        eq_(fmd_table_0.match['ip_proto'], inet.IPPROTO_ICMPV6)
        eq_(fmd_table_0.match['icmpv6_type'], icmpv6.MLD_LISTENER_QUERY)
        eq_(len(fmd_table_0.instructions), 1)
        eq_(fmd_table_0.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_0.instructions[0].actions), 1)
        eq_(fmd_table_0.instructions[0].actions[0].port,
            ofproto.OFPP_CONTROLLER)
        eq_(fmd_table_0.instructions[0].actions[0].max_len,
            ofproto.OFPCML_NO_BUFFER)

        # table 3
        fmd_table_3 = self.fmg[1]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_3.match['in_port'], apresia_12k.TAG2PBB)
        eq_(fmd_table_3.match['vlan_vid'], ivid)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 8)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].ethertype,
            ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.instructions[0].actions[2].key, 'pbb_isid')
        eq_(fmd_table_3.instructions[0].actions[2].value, pbb_isid)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'eth_dst')
        eq_(fmd_table_3.instructions[0].actions[3].value, '00:00:00:00:00:00')
        eq_(fmd_table_3.instructions[0].actions[4].key, 'eth_src')
        eq_(fmd_table_3.instructions[0].actions[4].value, "00:00:00:00:00:04")
        eq_(fmd_table_3.instructions[0].actions[5].ethertype,
            ether.ETH_TYPE_8021AD)
        eq_(fmd_table_3.instructions[0].actions[6].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[6].value, bvid)
        eq_(fmd_table_3.instructions[0].actions[7].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 60)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[3]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 59)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    # =========================================================================
    # 収容SW1(Apresia12000)の初期可処理
    # =========================================================================
    def test_initialize_flows_003(self):

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": 1,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        datapathid = 2
        ivid = 2001
        pbb_isid = 10001
        bvid = 4001

        self.fmg = flow_mod_generator(switch_infos)\
            .initialize_flows(datapathid, ivid, pbb_isid, bvid)

        eq_(len(self.fmg), 6)

        # table 0
        fmd_table_0 = self.fmg[0]
        eq_(fmd_table_0.datapathid, datapathid)
        eq_(fmd_table_0.table_id, 0)
        eq_(fmd_table_0.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_0.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_0.match['in_port'], 1)
        eq_(fmd_table_0.match['eth_type'], ether.ETH_TYPE_IPV6)
        eq_(fmd_table_0.match['ip_proto'], inet.IPPROTO_ICMPV6)
        eq_(fmd_table_0.match['icmpv6_type'], icmpv6.MLDV2_LISTENER_REPORT)
        eq_(len(fmd_table_0.instructions), 1)
        eq_(fmd_table_0.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_0.instructions[0].actions), 1)
        eq_(fmd_table_0.instructions[0].actions[0].port,
            ofproto.OFPP_CONTROLLER)
        eq_(fmd_table_0.instructions[0].actions[0].max_len,
            ofproto.OFPCML_NO_BUFFER)

        # table 0
        fmd_table_0 = self.fmg[1]
        eq_(fmd_table_0.datapathid, datapathid)
        eq_(fmd_table_0.table_id, 0)
        eq_(fmd_table_0.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_0.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_0.match['in_port'], 2)
        eq_(fmd_table_0.match['eth_type'], ether.ETH_TYPE_IPV6)
        eq_(fmd_table_0.match['ip_proto'], inet.IPPROTO_ICMPV6)
        eq_(fmd_table_0.match['icmpv6_type'], icmpv6.MLDV2_LISTENER_REPORT)
        eq_(len(fmd_table_0.instructions), 1)
        eq_(fmd_table_0.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_0.instructions[0].actions), 1)
        eq_(fmd_table_0.instructions[0].actions[0].port,
            ofproto.OFPP_CONTROLLER)
        eq_(fmd_table_0.instructions[0].actions[0].max_len,
            ofproto.OFPCML_NO_BUFFER)

        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 51)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 3
        fmd_table_3 = self.fmg[3]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_3.match['in_port'], apresia_12k.PBB2TAG)
        eq_(fmd_table_3.match['eth_type'], ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.match['pbb_isid'], pbb_isid)
        eq_(fmd_table_3.match['eth_dst'], "00:00:00:00:00:02")
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 5)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].type,
            OFPActionPopPbb().type)
        eq_(fmd_table_3.instructions[0].actions[1].len, OFPActionPopPbb().len)
        eq_(fmd_table_3.instructions[0].actions[2].ethertype,
            ether.ETH_TYPE_8021Q)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[3].value, ivid)
        eq_(fmd_table_3.instructions[0].actions[4].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[4]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | 1)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[5]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | 2)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    # =========================================================================
    # 収容SW2(Apresia12000)の初期可処理
    # =========================================================================
    def test_initialize_flows_004(self):

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": 1,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        datapathid = 3
        ivid = 2001
        pbb_isid = 10001
        bvid = 4001

        self.fmg = flow_mod_generator(switch_infos)\
            .initialize_flows(datapathid, ivid, pbb_isid, bvid)

        eq_(len(self.fmg), 4)

        # table 0
        fmd_table_0 = self.fmg[0]
        eq_(fmd_table_0.datapathid, datapathid)
        eq_(fmd_table_0.table_id, 0)
        eq_(fmd_table_0.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_0.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_0.match['in_port'], 1)
        eq_(fmd_table_0.match['eth_type'], ether.ETH_TYPE_IPV6)
        eq_(fmd_table_0.match['ip_proto'], inet.IPPROTO_ICMPV6)
        eq_(fmd_table_0.match['icmpv6_type'], icmpv6.MLDV2_LISTENER_REPORT)
        eq_(len(fmd_table_0.instructions), 1)
        eq_(fmd_table_0.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_0.instructions[0].actions), 1)
        eq_(fmd_table_0.instructions[0].actions[0].port,
            ofproto.OFPP_CONTROLLER)
        eq_(fmd_table_0.instructions[0].actions[0].max_len,
            ofproto.OFPCML_NO_BUFFER)

        # table 4
        fmd_table_4 = self.fmg[1]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 52)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 3
        fmd_table_3 = self.fmg[2]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_3.match['in_port'], apresia_12k.PBB2TAG)
        eq_(fmd_table_3.match['eth_type'], ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.match['pbb_isid'], pbb_isid)
        eq_(fmd_table_3.match['eth_dst'], "00:00:00:00:00:03")
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 5)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].type,
            OFPActionPopPbb().type)
        eq_(fmd_table_3.instructions[0].actions[1].len, OFPActionPopPbb().len)
        eq_(fmd_table_3.instructions[0].actions[2].ethertype,
            ether.ETH_TYPE_8021Q)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[3].value, ivid)
        eq_(fmd_table_3.instructions[0].actions[4].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[3]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | 1)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    # =========================================================================
    # datapath 2、 port 2 視聴開始(初回ユーザ参加)
    # =========================================================================
    def test_start_mg_001(self):

        edge_datapathid = 1

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        edge_sw_bmac = switch_infos[0]['sw_bmac']
        container_sw_bmac = switch_infos[1]['sw_bmac']

        self.fmg = flow_mod_generator(switch_infos).start_mg(multicast_address,
                                                             datapathid,
                                                             portno, ivid,
                                                             pbb_isid, bvid)

        # エッジSWのFlowModが3つ、収容SWのFlowModが3つ配列に格納される
        eq_(len(self.fmg), 6)

        # 以下、収容SWのFlowMod
        # table 4
        fmd_table_4 = self.fmg[0]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 51)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 3
        fmd_table_3 = self.fmg[1]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_3.match['in_port'], apresia_12k.PBB2TAG)
        # PBBデカプセル時のBVIDは省略可
        eq_(fmd_table_3.match['eth_type'], ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.match['pbb_isid'], pbb_isid)
        eq_(fmd_table_3.match['eth_dst'], container_sw_bmac)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 5)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].type,
            OFPActionPopPbb().type)
        eq_(fmd_table_3.instructions[0].actions[1].len, OFPActionPopPbb().len)
        eq_(fmd_table_3.instructions[0].actions[2].ethertype,
            ether.ETH_TYPE_8021Q)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[3].value, ivid)
        eq_(fmd_table_3.instructions[0].actions[4].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # 以下、エッジSWのFlowMod
        # table 2
        fmd_table_2 = self.fmg[3]
        eq_(fmd_table_2.datapathid, edge_datapathid)
        eq_(fmd_table_2.table_id, 2)
        eq_(fmd_table_2.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_2.match.iteritems():
            match_len += 1
        eq_(match_len, 3)
        eq_(fmd_table_2.match['in_port'], 2)
        eq_(fmd_table_2.match['eth_type'], ether.ETH_TYPE_IPV6)
        eq_(fmd_table_2.match['ipv6_dst'], multicast_address)
        eq_(len(fmd_table_2.instructions), 1)
        eq_(fmd_table_2.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_2.instructions[0].actions), 2)
        eq_(fmd_table_2.instructions[0].actions[0].key, 'vlan_vid')
        eq_(fmd_table_2.instructions[0].actions[0].value, ivid)
        eq_(fmd_table_2.instructions[0].actions[1].port, ofproto.OFPP_NORMAL)

        # table 3
        fmd_table_3 = self.fmg[4]
        eq_(fmd_table_3.datapathid, edge_datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_3.match['in_port'], apresia_12k.TAG2PBB)
        eq_(fmd_table_3.match['vlan_vid'], ivid)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 8)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].ethertype,
            ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.instructions[0].actions[2].key, 'pbb_isid')
        eq_(fmd_table_3.instructions[0].actions[2].value, pbb_isid)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'eth_dst')
        eq_(fmd_table_3.instructions[0].actions[3].value, '00:00:00:00:00:00')
        eq_(fmd_table_3.instructions[0].actions[4].key, 'eth_src')
        eq_(fmd_table_3.instructions[0].actions[4].value, edge_sw_bmac)
        eq_(fmd_table_3.instructions[0].actions[5].ethertype,
            ether.ETH_TYPE_8021AD)
        eq_(fmd_table_3.instructions[0].actions[6].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[6].value, bvid)
        eq_(fmd_table_3.instructions[0].actions[7].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[5]
        eq_(fmd_table_4.datapathid, edge_datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 49)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    # =========================================================================
    # datapath 3、port 1 視聴開始(初回ユーザ参加)
    # =========================================================================
    def test_start_mg_002(self):

        edge_datapathid = 1

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 3
        portno = 1
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        edge_sw_bmac = switch_infos[0]['sw_bmac']
        container_sw_bmac = switch_infos[2]['sw_bmac']

        self.fmg = flow_mod_generator(switch_infos).start_mg(multicast_address,
                                                             datapathid,
                                                             portno, ivid,
                                                             pbb_isid, bvid)

        # エッジSWのFlowModが3つ、収容SWのFlowModが3つ配列に格納される
        eq_(len(self.fmg), 6)

        # 以下、収容SWのFlowMod
        # table 4
        fmd_table_4 = self.fmg[0]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 52)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 3
        fmd_table_3 = self.fmg[1]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_3.match['in_port'], apresia_12k.PBB2TAG)
        # PBBデカプセル時のBVIDは省略可
        eq_(fmd_table_3.match['eth_type'], ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.match['pbb_isid'], pbb_isid)
        eq_(fmd_table_3.match['eth_dst'], container_sw_bmac)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 5)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].type,
            OFPActionPopPbb().type)
        eq_(fmd_table_3.instructions[0].actions[1].len, OFPActionPopPbb().len)
        eq_(fmd_table_3.instructions[0].actions[2].ethertype,
            ether.ETH_TYPE_8021Q)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[3].value, ivid)
        eq_(fmd_table_3.instructions[0].actions[4].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # 以下、エッジSWのFlowMod
        # table 2
        fmd_table_2 = self.fmg[3]
        eq_(fmd_table_2.datapathid, edge_datapathid)
        eq_(fmd_table_2.table_id, 2)
        eq_(fmd_table_2.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_2.match.iteritems():
            match_len += 1
        eq_(match_len, 3)
        eq_(fmd_table_2.match['in_port'], 2)
        eq_(fmd_table_2.match['eth_type'], ether.ETH_TYPE_IPV6)
        eq_(fmd_table_2.match['ipv6_dst'], multicast_address)
        eq_(len(fmd_table_2.instructions), 1)
        eq_(fmd_table_2.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_2.instructions[0].actions), 2)
        eq_(fmd_table_2.instructions[0].actions[0].key, 'vlan_vid')
        eq_(fmd_table_2.instructions[0].actions[0].value, ivid)
        eq_(fmd_table_2.instructions[0].actions[1].port, ofproto.OFPP_NORMAL)

        # table 3
        fmd_table_3 = self.fmg[4]
        eq_(fmd_table_3.datapathid, edge_datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_3.match['in_port'], apresia_12k.TAG2PBB)
        eq_(fmd_table_3.match['vlan_vid'], ivid)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 8)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].ethertype,
            ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.instructions[0].actions[2].key, 'pbb_isid')
        eq_(fmd_table_3.instructions[0].actions[2].value, pbb_isid)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'eth_dst')
        eq_(fmd_table_3.instructions[0].actions[3].value, '00:00:00:00:00:00')
        eq_(fmd_table_3.instructions[0].actions[4].key, 'eth_src')
        eq_(fmd_table_3.instructions[0].actions[4].value, edge_sw_bmac)
        eq_(fmd_table_3.instructions[0].actions[5].ethertype,
            ether.ETH_TYPE_8021AD)
        eq_(fmd_table_3.instructions[0].actions[6].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[6].value, bvid)
        eq_(fmd_table_3.instructions[0].actions[7].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[5]
        eq_(fmd_table_4.datapathid, edge_datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 50)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    # =========================================================================
    # SW1にport2を追加
    # =========================================================================
    def test_add_port_001(self):

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": 1,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        self.fmg = flow_mod_generator(switch_infos).add_port(multicast_address,
                                                             datapathid,
                                                             portno, ivid,
                                                             pbb_isid, bvid)

        eq_(len(self.fmg), 1)

        # table 4
        fmd_table_4 = self.fmg[0]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    # =========================================================================
    # SW1にport3を追加
    # =========================================================================
    def test_add_port_002(self):

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": 1,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 3
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        self.fmg = flow_mod_generator(switch_infos).add_port(multicast_address,
                                                             datapathid,
                                                             portno, ivid,
                                                             pbb_isid, bvid)

        eq_(len(self.fmg), 1)

        # table 4
        fmd_table_4 = self.fmg[0]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    # =========================================================================
    # SW1,port2を追加
    # =========================================================================
    def test_add_datapath_001(self):

        edge_datapathid = 1

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        edge_sw_bmac = switch_infos[0]['sw_bmac']
        container_sw_bmac = switch_infos[1]['sw_bmac']

        self.fmg = flow_mod_generator(switch_infos)\
            .add_datapath(multicast_address, datapathid, portno, ivid,
                          pbb_isid, bvid)

        eq_(len(self.fmg), 5)

        # 以下、収容SW
        # table 4
        fmd_table_4 = self.fmg[0]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 51)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 3
        fmd_table_3 = self.fmg[1]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_3.match['in_port'], apresia_12k.PBB2TAG)
        eq_(fmd_table_3.match['eth_type'], ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.match['pbb_isid'], pbb_isid)
        eq_(fmd_table_3.match['eth_dst'], container_sw_bmac)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 5)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].type,
            OFPActionPopPbb().type)
        eq_(fmd_table_3.instructions[0].actions[1].len, OFPActionPopPbb().len)
        eq_(fmd_table_3.instructions[0].actions[2].ethertype,
            ether.ETH_TYPE_8021Q)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[3].value, ivid)
        eq_(fmd_table_3.instructions[0].actions[4].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # 以下、エッジSW
        # table 3
        fmd_table_3 = self.fmg[3]
        eq_(fmd_table_3.datapathid, edge_datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_3.match['in_port'], apresia_12k.TAG2PBB)
        eq_(fmd_table_3.match['vlan_vid'], ivid)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 8)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].ethertype,
            ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.instructions[0].actions[2].key, 'pbb_isid')
        eq_(fmd_table_3.instructions[0].actions[2].value, pbb_isid)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'eth_dst')
        eq_(fmd_table_3.instructions[0].actions[3].value, '00:00:00:00:00:00')
        eq_(fmd_table_3.instructions[0].actions[4].key, 'eth_src')
        eq_(fmd_table_3.instructions[0].actions[4].value, edge_sw_bmac)
        eq_(fmd_table_3.instructions[0].actions[5].ethertype,
            ether.ETH_TYPE_8021AD)
        eq_(fmd_table_3.instructions[0].actions[6].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[6].value, bvid)
        eq_(fmd_table_3.instructions[0].actions[7].port, ofproto.OFPP_NORMAL)
        eq_(fmd_table_3.command, ofproto.OFPFC_MODIFY_STRICT)

        # table 4
        fmd_table_4 = self.fmg[4]
        eq_(fmd_table_4.datapathid, edge_datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 49)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    # =========================================================================
    # SW2,port1を追加
    # =========================================================================
    def test_add_datapath_002(self):

        edge_datapathid = 1

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 3
        portno = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        edge_sw_bmac = switch_infos[0]['sw_bmac']
        container_sw_bmac = switch_infos[2]['sw_bmac']

        self.fmg = flow_mod_generator(switch_infos)\
            .add_datapath(multicast_address, datapathid, portno, ivid,
                          pbb_isid, bvid)

        eq_(len(self.fmg), 5)

        # 以下、収容SW
        # table 4
        fmd_table_4 = self.fmg[0]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 52)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # table 3
        fmd_table_3 = self.fmg[1]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_3.match['in_port'], apresia_12k.PBB2TAG)
        eq_(fmd_table_3.match['eth_type'], ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.match['pbb_isid'], pbb_isid)
        eq_(fmd_table_3.match['eth_dst'], container_sw_bmac)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 5)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].type,
            OFPActionPopPbb().type)
        eq_(fmd_table_3.instructions[0].actions[1].len, OFPActionPopPbb().len)
        eq_(fmd_table_3.instructions[0].actions[2].ethertype,
            ether.ETH_TYPE_8021Q)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[3].value, ivid)
        eq_(fmd_table_3.instructions[0].actions[4].port, ofproto.OFPP_NORMAL)

        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

        # 以下、エッジSW
        # table 3
        fmd_table_3 = self.fmg[3]
        eq_(fmd_table_3.datapathid, edge_datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_3.match['in_port'], apresia_12k.TAG2PBB)
        eq_(fmd_table_3.match['vlan_vid'], ivid)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 8)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].ethertype,
            ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.instructions[0].actions[2].key, 'pbb_isid')
        eq_(fmd_table_3.instructions[0].actions[2].value, pbb_isid)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'eth_dst')
        eq_(fmd_table_3.instructions[0].actions[3].value, '00:00:00:00:00:00')
        eq_(fmd_table_3.instructions[0].actions[4].key, 'eth_src')
        eq_(fmd_table_3.instructions[0].actions[4].value, edge_sw_bmac)
        eq_(fmd_table_3.instructions[0].actions[5].ethertype,
            ether.ETH_TYPE_8021AD)
        eq_(fmd_table_3.instructions[0].actions[6].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[6].value, bvid)
        eq_(fmd_table_3.instructions[0].actions[7].port, ofproto.OFPP_NORMAL)
        eq_(fmd_table_3.command, ofproto.OFPFC_MODIFY_STRICT)

        # table 4
        fmd_table_4 = self.fmg[4]
        eq_(fmd_table_4.datapathid, edge_datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 50)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 1)
        eq_(fmd_table_4.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_4.instructions[0].actions), 1)
        eq_(fmd_table_4.instructions[0].actions[0].port, ofproto.OFPP_NORMAL)

    # =========================================================================
    # datapathid 2,port3 視聴終了
    # =========================================================================
    def test_remove_mg_001(self):

        edge_datapathid = 1

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 3
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        container_sw_bmac = switch_infos[1]['sw_bmac']

        self.fmg = flow_mod_generator(switch_infos)\
            .remove_mg(multicast_address, datapathid, portno, ivid, pbb_isid,
                       bvid)

        eq_(len(self.fmg), 6)

        # 以下、エッジSW
        # table 2
        fmd_table_2 = self.fmg[0]
        eq_(fmd_table_2.datapathid, edge_datapathid)
        eq_(fmd_table_2.table_id, 2)
        eq_(fmd_table_2.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_2.match.iteritems():
            match_len += 1
        eq_(match_len, 3)
        eq_(fmd_table_2.match['in_port'], 2)
        eq_(fmd_table_2.match['eth_type'], ether.ETH_TYPE_IPV6)
        eq_(fmd_table_2.match['ipv6_dst'], multicast_address)
        eq_(len(fmd_table_2.instructions), 0)
        eq_(fmd_table_2.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_2.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_2.out_group, ofproto.OFPG_ANY)

        # table 3
        fmd_table_3 = self.fmg[1]
        eq_(fmd_table_3.datapathid, edge_datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_3.match['in_port'], apresia_12k.TAG2PBB)
        eq_(fmd_table_3.match['vlan_vid'], ivid)
        eq_(len(fmd_table_3.instructions), 0)
        eq_(fmd_table_3.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_3.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_3.out_group, ofproto.OFPG_ANY)

        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, edge_datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 49)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

        # 以下、収容SW
        # table 4
        fmd_table_4 = self.fmg[3]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 51)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

        # table 3
        fmd_table_3 = self.fmg[4]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_3.match['in_port'], apresia_12k.PBB2TAG)
        eq_(fmd_table_3.match['eth_type'], ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.match['pbb_isid'], pbb_isid)
        eq_(fmd_table_3.match['eth_dst'], container_sw_bmac)
        eq_(len(fmd_table_3.instructions), 0)
        eq_(fmd_table_3.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_3.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_3.out_group, ofproto.OFPG_ANY)

        # table 4
        fmd_table_4 = self.fmg[5]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

    # =========================================================================
    # datapathid 3,port1 視聴終了
    # =========================================================================
    def test_remove_mg_002(self):

        edge_datapathid = 1

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 3
        portno = 1
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        container_sw_bmac = switch_infos[2]['sw_bmac']

        self.fmg = flow_mod_generator(switch_infos)\
            .remove_mg(multicast_address, datapathid, portno, ivid, pbb_isid,
                       bvid)

        eq_(len(self.fmg), 6)

        # 以下、エッジSW
        # table 2
        fmd_table_2 = self.fmg[0]
        eq_(fmd_table_2.datapathid, edge_datapathid)
        eq_(fmd_table_2.table_id, 2)
        eq_(fmd_table_2.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_2.match.iteritems():
            match_len += 1
        eq_(match_len, 3)
        eq_(fmd_table_2.match['in_port'], 2)
        eq_(fmd_table_2.match['eth_type'], ether.ETH_TYPE_IPV6)
        eq_(fmd_table_2.match['ipv6_dst'], multicast_address)
        eq_(len(fmd_table_2.instructions), 0)
        eq_(fmd_table_2.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_2.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_2.out_group, ofproto.OFPG_ANY)

        # table 3
        fmd_table_3 = self.fmg[1]
        eq_(fmd_table_3.datapathid, edge_datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_3.match['in_port'], apresia_12k.TAG2PBB)
        eq_(fmd_table_3.match['vlan_vid'], ivid)
        eq_(len(fmd_table_3.instructions), 0)
        eq_(fmd_table_3.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_3.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_3.out_group, ofproto.OFPG_ANY)

        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, edge_datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 50)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

        # 以下、収容SW
        # table 4
        fmd_table_4 = self.fmg[3]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 52)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

        # table 3
        fmd_table_3 = self.fmg[4]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_3.match['in_port'], apresia_12k.PBB2TAG)
        eq_(fmd_table_3.match['eth_type'], ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.match['pbb_isid'], pbb_isid)
        eq_(fmd_table_3.match['eth_dst'], container_sw_bmac)
        eq_(len(fmd_table_3.instructions), 0)
        eq_(fmd_table_3.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_3.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_3.out_group, ofproto.OFPG_ANY)

        # table 4
        fmd_table_4 = self.fmg[5]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

    # =========================================================================
    # SW1,port2 視聴終了
    # =========================================================================
    def test_remove_port_001(self):

        edge_datapathid = 1

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port": 2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        self.fmg = flow_mod_generator(switch_infos)\
            .remove_port(multicast_address, datapathid, portno, ivid, pbb_isid,
                         bvid)

        eq_(len(self.fmg), 1)

        # 以下、収容SW
        # table 4
        fmd_table_4 = self.fmg[0]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

    # =========================================================================
    # SW1,port3 視聴終了
    # =========================================================================
    def test_remove_port_002(self):

        edge_datapathid = 1

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port":  2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 3
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        self.fmg = flow_mod_generator(switch_infos)\
            .remove_port(multicast_address, datapathid, portno, ivid, pbb_isid,
                         bvid)

        eq_(len(self.fmg), 1)

        # 以下、収容SW
        # table 4
        fmd_table_4 = self.fmg[0]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

    # =========================================================================
    # SW1,port3 視聴終了
    # =========================================================================
    def test_remove_datapath_001(self):

        edge_datapathid = 1

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port":  2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
        }]

        multicast_address = 'ff38::1:1'
        datapathid = 2
        portno = 3
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        edge_sw_bmac = switch_infos[0]['sw_bmac']
        container_sw_bmac = switch_infos[1]['sw_bmac']

        self.fmg = flow_mod_generator(switch_infos)\
            .remove_datapath(multicast_address, datapathid, portno, ivid,
                             pbb_isid, bvid)

        eq_(len(self.fmg), 5)

        # 以下、収容SW
        # table 3
        fmd_table_3 = self.fmg[0]
        eq_(fmd_table_3.datapathid, edge_datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_3.match['in_port'], apresia_12k.TAG2PBB)
        eq_(fmd_table_3.match['vlan_vid'], ivid)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 8)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].ethertype,
            ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.instructions[0].actions[2].key, 'pbb_isid')
        eq_(fmd_table_3.instructions[0].actions[2].value, pbb_isid)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'eth_dst')
        eq_(fmd_table_3.instructions[0].actions[3].value, '00:00:00:00:00:00')
        eq_(fmd_table_3.instructions[0].actions[4].key, 'eth_src')
        eq_(fmd_table_3.instructions[0].actions[4].value, edge_sw_bmac)
        eq_(fmd_table_3.instructions[0].actions[5].ethertype,
            ether.ETH_TYPE_8021AD)
        eq_(fmd_table_3.instructions[0].actions[6].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[6].value, bvid)
        eq_(fmd_table_3.instructions[0].actions[7].port, ofproto.OFPP_NORMAL)
        eq_(fmd_table_3.command, ofproto.OFPFC_MODIFY_STRICT)

        # table 4
        fmd_table_4 = self.fmg[1]
        eq_(fmd_table_4.datapathid, edge_datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 49)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

        # 以下、収容SW
        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 51)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

        # table 3
        fmd_table_3 = self.fmg[3]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_3.match['in_port'], apresia_12k.PBB2TAG)
        eq_(fmd_table_3.match['eth_type'], ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.match['pbb_isid'], pbb_isid)
        eq_(fmd_table_3.match['eth_dst'], container_sw_bmac)
        eq_(len(fmd_table_3.instructions), 0)
        eq_(fmd_table_3.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_3.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_3.out_group, ofproto.OFPG_ANY)

        # table 4
        fmd_table_4 = self.fmg[4]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

    # =========================================================================
    # SW2,port1 視聴終了
    # =========================================================================
    def test_remove_datapath_002(self):

        edge_datapathid = 1

        switch_infos = [{
            "sw_name": "esw",
            "sw_type": 12000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port":  2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        },
            {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },
            {
            "sw_name": "sw2",
            "sw_type": 12000,
            "datapathid": 3,
            "sw_bmac": "00:00:00:00:00:03",
            "edge_switch_port": 52,
            "olt_ports": [1]
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
            .remove_datapath(multicast_address, datapathid, portno, ivid,
                             pbb_isid, bvid)

        eq_(len(self.fmg), 5)

        # 以下、収容SW
        # table 3
        fmd_table_3 = self.fmg[0]
        eq_(fmd_table_3.datapathid, edge_datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_3.match['in_port'], apresia_12k.TAG2PBB)
        eq_(fmd_table_3.match['vlan_vid'], ivid)
        eq_(len(fmd_table_3.instructions), 1)
        eq_(fmd_table_3.instructions[0].type, ofproto.OFPIT_APPLY_ACTIONS)
        eq_(len(fmd_table_3.instructions[0].actions), 8)
        eq_(fmd_table_3.instructions[0].actions[0].type,
            OFPActionPopVlan().type)
        eq_(fmd_table_3.instructions[0].actions[0].len, OFPActionPopVlan().len)
        eq_(fmd_table_3.instructions[0].actions[1].ethertype,
            ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.instructions[0].actions[2].key, 'pbb_isid')
        eq_(fmd_table_3.instructions[0].actions[2].value, pbb_isid)
        eq_(fmd_table_3.instructions[0].actions[3].key, 'eth_dst')
        eq_(fmd_table_3.instructions[0].actions[3].value, '00:00:00:00:00:00')
        eq_(fmd_table_3.instructions[0].actions[4].key, 'eth_src')
        eq_(fmd_table_3.instructions[0].actions[4].value, edge_sw_bmac)
        eq_(fmd_table_3.instructions[0].actions[5].ethertype,
            ether.ETH_TYPE_8021AD)
        eq_(fmd_table_3.instructions[0].actions[6].key, 'vlan_vid')
        eq_(fmd_table_3.instructions[0].actions[6].value, bvid)
        eq_(fmd_table_3.instructions[0].actions[7].port, ofproto.OFPP_NORMAL)
        eq_(fmd_table_3.command, ofproto.OFPFC_MODIFY_STRICT)

        # table 4
        fmd_table_4 = self.fmg[1]
        eq_(fmd_table_4.datapathid, edge_datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 50)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

        # 以下、収容SW
        # table 4
        fmd_table_4 = self.fmg[2]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x02000000 | 52)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

        # table 3
        fmd_table_3 = self.fmg[3]
        eq_(fmd_table_3.datapathid, datapathid)
        eq_(fmd_table_3.table_id, 3)
        eq_(fmd_table_3.priority, PRIORITY_NORMAL)
        match_len = 0
        for item in fmd_table_3.match.iteritems():
            match_len += 1
        eq_(match_len, 4)
        eq_(fmd_table_3.match['in_port'], apresia_12k.PBB2TAG)
        eq_(fmd_table_3.match['eth_type'], ether.ETH_TYPE_8021AH)
        eq_(fmd_table_3.match['pbb_isid'], pbb_isid)
        eq_(fmd_table_3.match['eth_dst'], container_sw_bmac)
        eq_(len(fmd_table_3.instructions), 0)
        eq_(fmd_table_3.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_3.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_3.out_group, ofproto.OFPG_ANY)

        # table 4
        fmd_table_4 = self.fmg[4]
        eq_(fmd_table_4.datapathid, datapathid)
        eq_(fmd_table_4.table_id, 4)
        eq_(fmd_table_4.priority, PRIORITY_LOW)
        match_len = 0
        for item in fmd_table_4.match.iteritems():
            match_len += 1
        eq_(match_len, 2)
        eq_(fmd_table_4.match['in_port'], 0x00000000 | portno)
        eq_(fmd_table_4.match['vlan_vid'], ivid)
        eq_(len(fmd_table_4.instructions), 0)
        eq_(fmd_table_4.command, ofproto.OFPFC_DELETE_STRICT)
        eq_(fmd_table_4.out_port, ofproto.OFPP_ANY)
        eq_(fmd_table_4.out_group, ofproto.OFPG_ANY)

    # =========================================================================
    # 以下、Apresia26000について(未実装なため、エラーが返ることの確認)
    # =========================================================================
    def test_initialize_flows_apresia_26k_001(self):

        edge_datapathid = 1

        switch_info = {
            "sw_name": "esw",
            "sw_type": 26000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port":  2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        }

        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        flow_mod_datas = []

        try:
            self.fmg = apresia_26k(switch_info)\
                .initialize_flows(ivid, pbb_isid, bvid, flow_mod_datas)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'Unsupported Operation')
            eq_(str(e), "'Unsupported Operation'")
            return

        raise Exception()

    def test_start_mg_edge_apresia_26k_001(self):

        edge_datapathid = 1

        switch_info = {
            "sw_name": "esw",
            "sw_type": 26000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port":  2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        }

        multicast_address = 'ff38::1:1'
        datapathid = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        flow_mod_datas = []

        try:
            self.fmg = apresia_26k(switch_info)\
                .start_mg_edge(multicast_address, datapathid, ivid, pbb_isid,
                               bvid, flow_mod_datas)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'Unsupported Operation')
            eq_(str(e), "'Unsupported Operation'")
            return

        raise Exception()

    def test_add_datapath_edge_apresia_26k_001(self):

        edge_datapathid = 1

        switch_info = {
            "sw_name": "esw",
            "sw_type": 26000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port":  2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        }

        multicast_address = 'ff38::1:1'
        datapathid = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        flow_mod_datas = []

        try:
            self.fmg = apresia_26k(switch_info)\
                .add_datapath_edge(multicast_address, datapathid, ivid,
                                   pbb_isid, bvid, flow_mod_datas)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'Unsupported Operation')
            eq_(str(e), "'Unsupported Operation'")
            return

        raise Exception()

    def test_remove_mg_edge_apresia_26k_001(self):

        edge_datapathid = 1

        switch_info = {
            "sw_name": "esw",
            "sw_type": 26000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port":  2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        }

        multicast_address = 'ff38::1:1'
        datapathid = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        flow_mod_datas = []

        try:
            self.fmg = apresia_26k(switch_info)\
                .remove_mg_edge(multicast_address, datapathid, ivid, pbb_isid,
                                bvid, flow_mod_datas)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'Unsupported Operation')
            eq_(str(e), "'Unsupported Operation'")
            return

        raise Exception()

    def test_remove_datapath_edge_apresia_26k_001(self):

        edge_datapathid = 1

        switch_info = {
            "sw_name": "esw",
            "sw_type": 26000,
            "datapathid": edge_datapathid,
            "sw_bmac": "00:00:00:00:00:01",
            "edge_router_port":  2,
            "mld_port": 1,
            "container_sw_ports": {
                "2": 49,
                "3": 50
            }
        }

        multicast_address = 'ff38::1:1'
        datapathid = 2
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        flow_mod_datas = []

        try:
            self.fmg = apresia_26k(switch_info)\
                .remove_datapath_edge(multicast_address, datapathid, ivid,
                                      pbb_isid, bvid, flow_mod_datas)

        except flow_mod_gen_exception as e:
            eq_(e.value, 'Unsupported Operation')
            eq_(str(e), "'Unsupported Operation'")
            return

        raise Exception()

    def test_start_mg_container_apresia_26k_001(self):

        switch_info = {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },

        portno = 1
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        flow_mod_datas = []

        try:
            self.fmg = apresia_26k(switch_info)\
                .start_mg_container(portno, ivid, pbb_isid, bvid,
                                    flow_mod_datas)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'Unsupported Operation')
            eq_(str(e), "'Unsupported Operation'")
            return

        raise Exception()

    def test_add_port_container_apresia_26k_001(self):

        switch_info = {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },

        portno = 1
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        flow_mod_datas = []

        try:
            self.fmg = apresia_26k(switch_info)\
                .add_port_container(portno, ivid, pbb_isid, bvid,
                                    flow_mod_datas)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'Unsupported Operation')
            eq_(str(e), "'Unsupported Operation'")
            return

        raise Exception()

    def test_remove_mg_container_apresia_26k_001(self):

        switch_info = {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },

        portno = 1
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        flow_mod_datas = []

        try:
            self.fmg = apresia_26k(switch_info)\
                .remove_mg_container(portno, ivid, pbb_isid, bvid,
                                     flow_mod_datas)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'Unsupported Operation')
            eq_(str(e), "'Unsupported Operation'")
            return

        raise Exception()

    def test_remove_port_container_apresia_26k_001(self):

        switch_info = {
            "sw_name": "sw1",
            "sw_type": 12000,
            "datapathid": 2,
            "sw_bmac": "00:00:00:00:00:02",
            "edge_switch_port": 51,
            "olt_ports": [1, 2, 3]
        },

        portno = 1
        ivid = 2011
        pbb_isid = 10011
        bvid = 4001

        flow_mod_datas = []

        try:
            self.fmg = apresia_26k(switch_info)\
                .remove_port_container(portno, ivid, pbb_isid, bvid,
                                       flow_mod_datas)
        except flow_mod_gen_exception as e:
            eq_(e.value, 'Unsupported Operation')
            eq_(str(e), "'Unsupported Operation'")
            return

        raise Exception()


if __name__ == "__main__":
    unittest.main()
