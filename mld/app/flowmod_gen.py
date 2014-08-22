# coding: utf-8

import sys
import os

from ryu.lib.packet import icmpv6
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.ofproto.ofproto_v1_3_parser import OFPActionPopVlan, OFPActionPushPbb, \
    OFPActionSetField, OFPActionPushVlan, OFPActionPopPbb

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
COMMON_PATH = DIR_PATH + "/../../common/"
sys.path.append(COMMON_PATH)
import mld_const as const
from zmq_dispatch import flow_mod_data

# =============================================================================
# フローテーブルのプライオリティ
# =============================================================================
PRIORITY_NORMAL = ofproto.OFP_DEFAULT_PRIORITY


# =============================================================================
# FlowModのジェネレータ
# =============================================================================
class flow_mod_generator(object):

    def __init__(self, switch_infos):

        self.edge_switchs = []
        self.container_switches = {}
        self.all_switches = {}

        for switch_info in switch_infos:

            datapathid = switch_info[const.SW_TAG_DATAPATHID]
            sw_type = switch_info[const.SW_TAG_TYPE]

            flow_mod_gen_impl = None
            if sw_type == const.SW_TYPE_12K:
                flow_mod_gen_impl = apresia_12k(switch_info)
            elif sw_type == const.SW_TYPE_26K:
                flow_mod_gen_impl = apresia_26k(switch_info)
            else:
                raise flow_mod_gen_exception("Unsupported sw_type:" +
                                             str(sw_type) + ", datapathid=" +
                                             str(datapathid) + ".")

            if switch_info[const.SW_TAG_NAME] == const.SW_NAME_ESW:
                self.edge_switchs.append(flow_mod_gen_impl)
            else:
                self.container_switches[datapathid] = flow_mod_gen_impl
            self.all_switches[datapathid] = flow_mod_gen_impl

        if len(self.edge_switchs) == 0:
            raise flow_mod_gen_exception("edge switch is not defined.")
        if len(self.container_switches) == 0:
            raise flow_mod_gen_exception("container switch is not defined.")

    # =========================================================================
    # 初期フロー
    # =========================================================================
    def initialize_flows(self, datapathid, ivid, pbb_isid, bvid):
        flow_mod_datas = []
        self.all_switches[datapathid].initialize_flows(ivid, pbb_isid, bvid,
                                                       flow_mod_datas)
        return flow_mod_datas

    # =========================================================================
    # 試聴開始(初回ユーザ参加)/試聴開始(MGで初回ユーザ)
    # =========================================================================
    def start_mg(self, multicast_address, datapathid, portno, mc_ivid, ivid,
                 pbb_isid, bvid):
        flow_mod_datas = []
        self.container_switches[datapathid].start_mg_container(portno, ivid,
                                                               pbb_isid, bvid,
                                                               flow_mod_datas)
        for edge_switch in self.edge_switchs:
            edge_switch.start_mg_edge(multicast_address, datapathid, mc_ivid,
                                      ivid, pbb_isid, bvid, flow_mod_datas)
        return flow_mod_datas

    # =========================================================================
    # 試聴開始(収納ポートで初回、同一収納SWにユーザ既存)
    # =========================================================================
    def add_port(self, multicast_address, datapathid, portno, ivid, pbb_isid,
                 bvid):
        flow_mod_datas = []
        self.container_switches[datapathid].add_port_container(portno, ivid,
                                                               pbb_isid, bvid,
                                                               flow_mod_datas)
        return flow_mod_datas

    # =========================================================================
    # 試聴開始(収納SWで初回ユーザ)
    # =========================================================================
    def add_datapath(self, multicast_address, datapathid, portno, ivid,
                     pbb_isid, bvid):
        flow_mod_datas = []
        # 収容スイッチに設定するフローはstartMG時と同じ
        self.container_switches[datapathid].start_mg_container(portno, ivid,
                                                               pbb_isid, bvid,
                                                               flow_mod_datas)
        for edge_switch in self.edge_switchs:
            edge_switch.add_datapath_edge(multicast_address, datapathid, ivid,
                                          pbb_isid, bvid, flow_mod_datas)
        return flow_mod_datas

    # =========================================================================
    # 試聴終了(MGで最終ユーザ)/試聴終了(最終ユーザの離脱)
    # =========================================================================
    def remove_mg(self, multicast_address, datapathid, portno, mc_ivid, ivid,
                  pbb_isid, bvid):
        flow_mod_datas = []
        for edge_switch in self.edge_switchs:
            edge_switch.remove_mg_edge(multicast_address, datapathid, mc_ivid,
                                       ivid, pbb_isid, bvid, flow_mod_datas)
        self.container_switches[datapathid].remove_mg_container(portno, ivid,
                                                                pbb_isid, bvid,
                                                                flow_mod_datas)
        return flow_mod_datas

    # =========================================================================
    # 試聴終了(収納ポートで最終、同一収納SWにユーザ残存)
    # =========================================================================
    def remove_port(self, multicast_address, datapathid, portno, ivid,
                    pbb_isid, bvid):
        flow_mod_datas = []
        self.container_switches[datapathid]\
            .remove_port_container(portno, ivid, pbb_isid, bvid,
                                   flow_mod_datas)
        return flow_mod_datas

    # =========================================================================
    # 試聴終了(収納SWで最終ユーザ)
    # =========================================================================
    def remove_datapath(self, multicast_address, datapathid, portno, ivid,
                        pbb_isid, bvid):
        flow_mod_datas = []
        for edge_switch in self.edge_switchs:
            edge_switch.remove_datapath_edge(multicast_address, datapathid,
                                             ivid, pbb_isid, bvid,
                                             flow_mod_datas)
        # 収容スイッチに設定するフローはremoveMG時と同じ
        self.container_switches[datapathid].remove_mg_container(portno, ivid,
                                                                pbb_isid, bvid,
                                                                flow_mod_datas)
        return flow_mod_datas


# =============================================================================
# スイッチに応じたFlowModデータ生成クラスの共通インターフェース定義
# =============================================================================
class flow_mod_gen_impl(object):

    def __init__(self, switch_info):
        self.switch_info = switch_info

    def initialize_flows(self, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_exception("Unsupported Operation.")

    def start_mg_edge(self, multicast_address, datapathid, mc_ivid, ivid,
                      pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_exception("Unsupported Operation.")

    def add_datapath_edge(self, multicast_address, datapathid, ivid, pbb_isid,
                          bvid, flow_mod_datas):
        raise flow_mod_gen_exception("Unsupported Operation.")

    def remove_mg_edge(self, multicast_address, datapathid, mc_ivid, ivid,
                       pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_exception("Unsupported Operation.")

    def remove_datapath_edge(self, multicast_address, datapathid, ivid,
                             pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_exception("Unsupported Operation.")

    def start_mg_container(self, portno, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_exception("Unsupported Operation.")

    def add_port_container(self, portno, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_exception("Unsupported Operation.")

    def remove_mg_container(self, portno, ivid, pbb_isid, bvid,
                            flow_mod_datas):
        raise flow_mod_gen_exception("Unsupported Operation.")

    def remove_port_container(self, portno, ivid, pbb_isid, bvid,
                              flow_mod_datas):
        raise flow_mod_gen_exception("Unsupported Operation.")

    # MLD QueryのPacketIn
    def make_flow_mld_query_packet_in(self,
                                      datapathid, in_port, flow_mod_datas):
        table_id = 0
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=in_port, eth_type=ether.ETH_TYPE_IPV6,
                                ip_proto=inet.IPPROTO_ICMPV6,
                                icmpv6_type=icmpv6.MLD_LISTENER_QUERY)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        flow_mod_datas.append(flow_mod_data(datapathid=datapathid,
                                            table_id=table_id,
                                            priority=priority,
                                            match=match,
                                            instructions=inst))

    # MLDv2 ReportのPacketIn
    def make_flow_mld_v2_report_packet_in(self,
                                          datapathid, in_port, flow_mod_datas):
        table_id = 0
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=in_port, eth_type=ether.ETH_TYPE_IPV6,
                                ip_proto=inet.IPPROTO_ICMPV6,
                                icmpv6_type=icmpv6.MLDV2_LISTENER_REPORT)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        flow_mod_datas.append(flow_mod_data(datapathid=datapathid,
                                            table_id=table_id,
                                            priority=priority,
                                            match=match,
                                            instructions=inst))

    # チャネル毎の内部VIDマッピング
    def make_flow_channel_ivid_mapping(self, command,
                                       datapathid, in_port, multicast_address,
                                       mc_ivid, ivid, flow_mod_datas):
        table_id = 2
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=in_port, vlan_vid=mc_ivid,
                                eth_type=ether.ETH_TYPE_IPV6,
                                ipv6_dst=multicast_address)

        inst = None
        out_port = 0
        out_group = 0
        if command != ofproto.OFPFC_DELETE_STRICT:
            actions = [OFPActionSetField(vlan_vid=ivid),
                       parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        else:
            inst = []
            out_port = ofproto.OFPP_ANY
            out_group = ofproto.OFPG_ANY

        flow_mod_datas.append(flow_mod_data(datapathid=datapathid,
                                            table_id=table_id,
                                            priority=priority,
                                            match=match,
                                            instructions=inst,
                                            command=command,
                                            out_port=out_port,
                                            out_group=out_group))

    # PBBカプセル化
    def make_flow_pbb_capsule(self, command,
                              datapathid, in_port, ivid, pbb_isid, bvid,
                              flow_mod_datas):
        table_id = 3
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=in_port, vlan_vid=ivid)

        inst = None
        out_port = 0
        out_group = 0
        if command != ofproto.OFPFC_DELETE_STRICT:
            actions = [OFPActionPopVlan(),
                       OFPActionPushPbb(ethertype=ether.ETH_TYPE_8021AH),
                       OFPActionSetField(pbb_isid=pbb_isid),
                       OFPActionSetField(eth_dst="00:00:00:00:00:00"),
                       OFPActionSetField(eth_src=self.
                                         switch_info[const.SW_TAG_BMAC]),
                       OFPActionPushVlan(ethertype=ether.ETH_TYPE_8021AD),
                       OFPActionSetField(vlan_vid=bvid),
                       parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        else:
            inst = []
            out_port = ofproto.OFPP_ANY
            out_group = ofproto.OFPG_ANY

        flow_mod_datas.append(flow_mod_data(datapathid=datapathid,
                                            table_id=table_id,
                                            priority=priority,
                                            match=match,
                                            instructions=inst,
                                            command=command,
                                            out_port=out_port,
                                            out_group=out_group))

    # PBBデカプセル化
    def make_flow_pbb_decapsule(self, command, datapathid,
                                in_port, ivid, pbb_isid, flow_mod_datas):
        table_id = 3
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=in_port,
                                eth_type=ether.ETH_TYPE_8021AH,
                                pbb_isid=pbb_isid,
                                eth_dst=self.switch_info[const.SW_TAG_BMAC])

        inst = None
        out_port = 0
        out_group = 0
        if command != ofproto.OFPFC_DELETE_STRICT:
            actions = [OFPActionPopVlan(),
                       OFPActionPopPbb(),
                       OFPActionPushVlan(ethertype=ether.ETH_TYPE_8021Q),
                       OFPActionSetField(vlan_vid=ivid),
                       parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        else:
            inst = []
            out_port = ofproto.OFPP_ANY
            out_group = ofproto.OFPG_ANY

        flow_mod_datas.append(flow_mod_data(datapathid=datapathid,
                                            table_id=table_id,
                                            priority=priority,
                                            match=match,
                                            instructions=inst,
                                            command=command,
                                            out_port=out_port,
                                            out_group=out_group))

    # VLAN設定
    def make_flow_vlan_setting(self, command,
                               datapathid, in_port, ivid, flow_mod_datas):
        table_id = 4
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=in_port, vlan_vid=ivid)

        inst = None
        out_port = 0
        out_group = 0
        if command != ofproto.OFPFC_DELETE_STRICT:
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        else:
            inst = []
            out_port = ofproto.OFPP_ANY
            out_group = ofproto.OFPG_ANY

        flow_mod_datas.append(flow_mod_data(datapathid=datapathid,
                                            table_id=table_id,
                                            priority=priority,
                                            match=match,
                                            instructions=inst,
                                            command=command,
                                            out_port=out_port,
                                            out_group=out_group))


# =============================================================================
# Apresia 12000 シリーズ
# =============================================================================
class apresia_12k(flow_mod_gen_impl):

    # 論理ポート定義
    TAG2PBB = 0xffff0001
    PBB2TAG = 0xffff0002

    def __init__(self, switch_info):
        super(apresia_12k, self).__init__(switch_info)

    def initialize_flows(self, ivid, pbb_isid, bvid, flow_mod_datas):

        datapathid = self.switch_info[const.SW_TAG_DATAPATHID]

        if self.switch_info[const.SW_TAG_NAME] == const.SW_NAME_ESW:

            edge_router_port = self.switch_info[const.SW_TAG_EDGE_ROUTER_PORT]
            container_sw_ports = self.switch_info[const.SW_TAG_CONTEINER_PORTS]

            # MLD QueryのPacket-In
            in_port = self.logical_port_untag(edge_router_port)
            self.make_flow_mld_query_packet_in(datapathid,
                                               in_port, flow_mod_datas)

            # MLD QueryのPBBカプセル化
            in_port = apresia_12k.TAG2PBB
            self.make_flow_pbb_capsule(ofproto.OFPFC_ADD, datapathid,
                                       in_port, ivid, pbb_isid, bvid,
                                       flow_mod_datas)

            # MLD QueryのVLAN設定(PBB出力側)
            for container_sw_port in container_sw_ports:
                in_port = self.logical_port_pbb(container_sw_port)
                self.make_flow_vlan_setting(ofproto.OFPFC_ADD,
                                            datapathid, in_port, ivid,
                                            flow_mod_datas)

        else:

            edge_switch_port = self.switch_info[const.SW_TAG_EDGE_SWITCH_PORT]
            olt_ports = self.switch_info[const.SW_TAG_OLT_PORTS]

            # MLDv2 ReportのPacket-In
            for olt_port in olt_ports:
                in_port = self.logical_port_untag(olt_port)
                self.make_flow_mld_v2_report_packet_in(datapathid, in_port,
                                                       flow_mod_datas)

            # MLD QueryのVLAN設定(PBB入力側）
            in_port = self.logical_port_pbb(edge_switch_port)
            self.make_flow_vlan_setting(ofproto.OFPFC_ADD, datapathid,
                                        in_port, ivid, flow_mod_datas)

            # MLD QueryのPBBデカプセル化
            in_port = apresia_12k.PBB2TAG
            self.make_flow_pbb_decapsule(ofproto.OFPFC_ADD,
                                         datapathid, in_port, ivid, pbb_isid,
                                         flow_mod_datas)

            # MLD QueryのVLAN設定(OLT出力側)
            for olt_port in olt_ports:
                in_port = self.logical_port_untag(olt_port)
                self.make_flow_vlan_setting(ofproto.OFPFC_ADD,
                                            datapathid, in_port, ivid,
                                            flow_mod_datas)

    def start_mg_edge(self, multicast_address, datapathid, mc_ivid,
                      ivid, pbb_isid, bvid, flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]
        edge_router_port = self.switch_info[const.SW_TAG_EDGE_ROUTER_PORT]
        container_sw_ports = self.switch_info[const.SW_TAG_CONTEINER_PORTS]

        # チャネル毎の内部VLANマッピング
        in_port = self.logical_port_untag(edge_router_port)
        self.make_flow_channel_ivid_mapping(ofproto.OFPFC_ADD,
                                            mydpid, in_port, multicast_address,
                                            mc_ivid, ivid, flow_mod_datas)

        # PBBカプセル化
        in_port = apresia_12k.TAG2PBB
        self.make_flow_pbb_capsule(ofproto.OFPFC_ADD,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

        # VLAN設定(PBB出力側)
        for container_sw_port in container_sw_ports:
            in_port = self.logical_port_pbb(container_sw_port)
            self.make_flow_vlan_setting(ofproto.OFPFC_ADD, mydpid,
                                        in_port, ivid, flow_mod_datas)

    # multicast_addressは使用しない
    def add_datapath_edge(self, multicast_address, datapathid, ivid, pbb_isid,
                          bvid, flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]

        # PBBカプセル化
        in_port = apresia_12k.TAG2PBB
        self.make_flow_pbb_capsule(ofproto.OFPFC_MODIFY_STRICT,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

    # bvidは使用しない
    def remove_mg_edge(self, multicast_address, datapathid, mc_ivid,
                       ivid, pbb_isid, bvid, flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]
        edge_router_port = self.switch_info[const.SW_TAG_EDGE_ROUTER_PORT]
        container_sw_ports = self.switch_info[const.SW_TAG_CONTEINER_PORTS]

        # チャネル毎の内部VLANマッピング
        in_port = self.logical_port_untag(edge_router_port)
        self.make_flow_channel_ivid_mapping(ofproto.OFPFC_DELETE_STRICT,
                                            mydpid, in_port, multicast_address,
                                            mc_ivid, ivid, flow_mod_datas)

        # PBBカプセル化
        in_port = apresia_12k.TAG2PBB
        self.make_flow_pbb_capsule(ofproto.OFPFC_DELETE_STRICT,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

        # VLAN設定(PBB出力側)
        for container_sw_port in container_sw_ports:
            in_port = self.logical_port_pbb(container_sw_port)
            self.make_flow_vlan_setting(ofproto.OFPFC_DELETE_STRICT,
                                        mydpid, in_port, ivid,
                                        flow_mod_datas)

    # multicast_addressは使用しない
    def remove_datapath_edge(self, multicast_address, datapathid, ivid,
                             pbb_isid, bvid, flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]

        # PBBカプセル化
        in_port = apresia_12k.TAG2PBB
        self.make_flow_pbb_capsule(ofproto.OFPFC_MODIFY_STRICT,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

    # bvidは使用しない
    def start_mg_container(self, portno, ivid, pbb_isid, bvid, flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]
        edge_switch_port = self.switch_info[const.SW_TAG_EDGE_SWITCH_PORT]

        # VLAN設定（PBB入力側)
        in_port = self.logical_port_pbb(edge_switch_port)
        self.make_flow_vlan_setting(ofproto.OFPFC_ADD,
                                    mydpid, in_port, ivid, flow_mod_datas)

        # PBBデカプセル化
        in_port = apresia_12k.PBB2TAG
        self.make_flow_pbb_decapsule(ofproto.OFPFC_ADD,
                                     mydpid, in_port, ivid, pbb_isid,
                                     flow_mod_datas)

        # VLAN設定(OLT出力側）
        in_port = self.logical_port_untag(portno)
        self.make_flow_vlan_setting(ofproto.OFPFC_ADD,
                                    mydpid, in_port, ivid, flow_mod_datas)

    # pbb_isid, bvidは使用しない
    def add_port_container(self, portno, ivid, pbb_isid, bvid, flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]

        # VLAN設定(OLT出力側）
        in_port = self.logical_port_untag(portno)
        self.make_flow_vlan_setting(ofproto.OFPFC_ADD,
                                    mydpid, in_port, ivid, flow_mod_datas)

    # bvidは使用しない
    def remove_mg_container(self, portno, ivid, pbb_isid, bvid,
                            flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]
        edge_switch_port = self.switch_info[const.SW_TAG_EDGE_SWITCH_PORT]

        # VLAN設定（PBB入力側)
        in_port = self.logical_port_pbb(edge_switch_port)
        self.make_flow_vlan_setting(ofproto.OFPFC_DELETE_STRICT,
                                    mydpid, in_port, ivid, flow_mod_datas)

        # PBBデカプセル化
        in_port = apresia_12k.PBB2TAG
        self.make_flow_pbb_decapsule(ofproto.OFPFC_DELETE_STRICT,
                                     mydpid, in_port, ivid, pbb_isid,
                                     flow_mod_datas)

        # VLAN設定(OLT出力側）
        in_port = self.logical_port_untag(portno)
        self.make_flow_vlan_setting(ofproto.OFPFC_DELETE_STRICT,
                                    mydpid, in_port, ivid, flow_mod_datas)

    # pbb_isid、bvidは使用しない
    def remove_port_container(self, portno, ivid, pbb_isid, bvid,
                              flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]

        # VLAN設定(OLT出力側）
        in_port = self.logical_port_untag(portno)
        self.make_flow_vlan_setting(ofproto.OFPFC_DELETE_STRICT,
                                    mydpid, in_port, ivid, flow_mod_datas)

    def logical_port_untag(self, portno):
        return 0x00000000 | portno

#     現状の実装では未使用
#     def logical_port_tag(self, portno):
#        return 0x01000000 | portno

    def logical_port_pbb(self, portno):
        return 0x02000000 | portno


# =============================================================================
# Apresia 26000 シリーズ
# =============================================================================
class apresia_26k(flow_mod_gen_impl):

    def __init__(self, switch_info):
        super(apresia_26k, self).__init__(switch_info)

    def initialize_flows(self, ivid, pbb_isid, bvid, flow_mod_datas):

        datapathid = self.switch_info[const.SW_TAG_DATAPATHID]

        if self.switch_info[const.SW_TAG_NAME] == const.SW_NAME_ESW:

            edge_router_port = self.switch_info[const.SW_TAG_EDGE_ROUTER_PORT]
            fcrp_sw_port = self.switch_info[const.SW_TAG_FCRP_PORT]
            container_sw_port = self.switch_info[const.SW_TAG_CONTEINER_PORT]

            # MLD QueryのPacket-In
            in_port = self.logical_port_untag(edge_router_port)
            self.make_flow_mld_query_packet_in(datapathid,
                                               in_port, flow_mod_datas)

            # MLD QueryのPBBカプセル化
            in_port = self.port_tag2pbb(fcrp_sw_port[const.SW_TAG_PHYSICAL])
            self.make_flow_pbb_capsule(ofproto.OFPFC_ADD, datapathid,
                                       in_port, ivid, pbb_isid, bvid,
                                       flow_mod_datas)

            in_port = self.port_tag2pbb(
                container_sw_port[const.SW_TAG_PHYSICAL])
            self.make_flow_pbb_capsule(ofproto.OFPFC_ADD, datapathid,
                                       in_port, ivid, pbb_isid, bvid,
                                       flow_mod_datas)

            # MLD QueryのVLAN設定(PBB出力側)
            in_port = self.fcrp_port_pbb(fcrp_sw_port[const.SW_TAG_FCRP])
            self.make_flow_vlan_setting(ofproto.OFPFC_ADD,
                                        datapathid, in_port, ivid,
                                        flow_mod_datas)

            in_port = self.lag_port_pbb(container_sw_port[const.SW_TAG_LAG])
            self.make_flow_vlan_setting(ofproto.OFPFC_ADD,
                                        datapathid, in_port, ivid,
                                        flow_mod_datas)

        else:
            raise flow_mod_gen_exception("Unsupported Operation.")

    def start_mg_edge(self, multicast_address, datapathid, mc_ivid,
                      ivid, pbb_isid, bvid, flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]
        edge_router_port = self.switch_info[const.SW_TAG_EDGE_ROUTER_PORT]
        fcrp_sw_port = self.switch_info[const.SW_TAG_FCRP_PORT]
        container_sw_port = self.switch_info[const.SW_TAG_CONTEINER_PORT]

        # チャネル毎の内部VLANマッピング
        in_port = self.logical_port_untag(edge_router_port)
        self.make_flow_channel_ivid_mapping(ofproto.OFPFC_ADD,
                                            mydpid, in_port, multicast_address,
                                            mc_ivid, ivid, flow_mod_datas)

        # PBBカプセル化
        in_port = self.port_tag2pbb(fcrp_sw_port[const.SW_TAG_PHYSICAL])
        self.make_flow_pbb_capsule(ofproto.OFPFC_ADD,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

        in_port = self.port_tag2pbb(container_sw_port[const.SW_TAG_PHYSICAL])
        self.make_flow_pbb_capsule(ofproto.OFPFC_ADD,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

        # VLAN設定(PBB出力側)
        in_port = self.fcrp_port_pbb(fcrp_sw_port[const.SW_TAG_FCRP])
        self.make_flow_vlan_setting(ofproto.OFPFC_ADD,
                                    mydpid, in_port, ivid,
                                    flow_mod_datas)

        in_port = self.lag_port_pbb(container_sw_port[const.SW_TAG_LAG])
        self.make_flow_vlan_setting(ofproto.OFPFC_ADD,
                                    mydpid, in_port, ivid,
                                    flow_mod_datas)

    # multicast_addressは使用しない
    def add_datapath_edge(self, multicast_address, datapathid, ivid, pbb_isid,
                          bvid, flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]
        fcrp_sw_port = self.switch_info[const.SW_TAG_FCRP_PORT]
        container_sw_port = self.switch_info[const.SW_TAG_CONTEINER_PORT]

        # PBBカプセル化
        in_port = self.port_tag2pbb(fcrp_sw_port[const.SW_TAG_PHYSICAL])
        self.make_flow_pbb_capsule(ofproto.OFPFC_MODIFY_STRICT,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

        in_port = self.port_tag2pbb(container_sw_port[const.SW_TAG_PHYSICAL])
        self.make_flow_pbb_capsule(ofproto.OFPFC_MODIFY_STRICT,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

    # bvidは使用しない
    def remove_mg_edge(self, multicast_address, datapathid, mc_ivid,
                       ivid, pbb_isid, bvid, flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]
        edge_router_port = self.switch_info[const.SW_TAG_EDGE_ROUTER_PORT]
        fcrp_sw_port = self.switch_info[const.SW_TAG_FCRP_PORT]
        container_sw_port = self.switch_info[const.SW_TAG_CONTEINER_PORT]

        # チャネル毎の内部VLANマッピング
        in_port = self.logical_port_untag(edge_router_port)
        self.make_flow_channel_ivid_mapping(ofproto.OFPFC_DELETE_STRICT,
                                            mydpid, in_port, multicast_address,
                                            mc_ivid, ivid, flow_mod_datas)

        # PBBカプセル化
        in_port = self.port_tag2pbb(fcrp_sw_port[const.SW_TAG_PHYSICAL])
        self.make_flow_pbb_capsule(ofproto.OFPFC_DELETE_STRICT,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

        in_port = self.port_tag2pbb(container_sw_port[const.SW_TAG_PHYSICAL])
        self.make_flow_pbb_capsule(ofproto.OFPFC_DELETE_STRICT,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

        # VLAN設定(PBB出力側)
        in_port = self.fcrp_port_pbb(fcrp_sw_port[const.SW_TAG_FCRP])
        self.make_flow_vlan_setting(ofproto.OFPFC_DELETE_STRICT,
                                    mydpid, in_port, ivid,
                                    flow_mod_datas)

        in_port = self.lag_port_pbb(container_sw_port[const.SW_TAG_LAG])
        self.make_flow_vlan_setting(ofproto.OFPFC_DELETE_STRICT,
                                    mydpid, in_port, ivid,
                                    flow_mod_datas)

    # multicast_addressは使用しない
    def remove_datapath_edge(self, multicast_address, datapathid, ivid,
                             pbb_isid, bvid, flow_mod_datas):

        mydpid = self.switch_info[const.SW_TAG_DATAPATHID]
        fcrp_sw_port = self.switch_info[const.SW_TAG_FCRP_PORT]
        container_sw_port = self.switch_info[const.SW_TAG_CONTEINER_PORT]

        # PBBカプセル化
        in_port = self.port_tag2pbb(fcrp_sw_port[const.SW_TAG_PHYSICAL])
        self.make_flow_pbb_capsule(ofproto.OFPFC_MODIFY_STRICT,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

        in_port = self.port_tag2pbb(container_sw_port[const.SW_TAG_PHYSICAL])
        self.make_flow_pbb_capsule(ofproto.OFPFC_MODIFY_STRICT,
                                   mydpid, in_port, ivid, pbb_isid, bvid,
                                   flow_mod_datas)

    def logical_port_untag(self, portno):
        return 0x00000000 | portno

#     現状の実装では未使用
#     def logical_port_tag(self, portno):
#        return 0x01000000 | portno

#     現状の実装では未使用
#     def logical_port_pbb(self, portno):
#         return 0x02000000 | portno

    def lag_port_pbb(self, portno):
        return 0x02010000 | portno

    def fcrp_port_pbb(self, portno):
        return 0x02030000 | portno

    def port_tag2pbb(self, portno):
        return 0xfffd0000 | portno

#     現状の実装では未使用
#     def port_pbb2tag(self, portno):
#         return 0xfffe0000 | portno


# =============================================================================
# FlowModジェネレータの例外クラス
# =============================================================================
class flow_mod_gen_exception(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
