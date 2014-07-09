# coding: utf-8

from ryu.lib.packet import icmpv6
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.ofproto.ofproto_v1_3_parser import OFPActionPopVlan, OFPActionPushPbb, \
    OFPActionSetField, OFPActionPushVlan, OFPActionPopPbb
import sys
sys.path.append('../../common')
from zmq_dispatch import flow_mod_data


PRIORITY_NORMAL = 1
PRIORITY_LOW = 0

'''
FlowModのジェネレータ
'''
class flow_mod_generator(object):

    def __init__(self, switch_infos):
        
        self.edge_switch = None
        self.container_switches = {}
        self.all_switch = {}
        
        for switch_info in switch_infos:
            
            datapathid = switch_info['datapathid']
            sw_type = switch_info['sw_type']
            
            flow_mod_gen_impl = None
            if sw_type == 12000:
                flow_mod_gen_impl = apresia_12k(switch_info)
            elif sw_type == 26000:
                flow_mod_gen_impl = apresia_26k(switch_info)
            else:
                raise flow_mod_gen_excepion('Unsupported sw_type:' + str(sw_type) + ', datapathid=' + datapathid)
            
            if switch_info['sw_name'] == 'esw':
                self.edge_switch = flow_mod_gen_impl
            else:
                self.container_switches[datapathid] = flow_mod_gen_impl
            self.all_switch[datapathid] = flow_mod_gen_impl
            
    '''
    初期フロー
    '''
    def initialize_flows(self, datapathid, ivid, pbb_isid, bvid):
        return self.all_switch[datapathid].initialize_flows(ivid, pbb_isid, bvid)
    
    '''
    試聴開始(初回ユーザ参加)/試聴開始(MGで初回ユーザ)
    '''    
    def start_mg(self, multicast_address, datapathid, portno, ivid, pbb_isid, bvid):
        flow_mod_datas = []
        self.edge_switch.start_mg_edge(multicast_address, datapathid, pbb_isid, ivid, bvid, flow_mod_datas)
        self.container_switches[datapathid].start_mg_container(datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas)
        return flow_mod_datas;
    
    '''
    試聴開始(収納ポートで初回、同一収納SWにユーザ既存)
    '''  
    def add_port(self, muticast_address, datapathid, portno, ivid, pbb_isid, bvid):
        flow_mod_datas = []
        self.container_switches[datapathid].add_port_container(datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas)
        return flow_mod_datas;

    '''
    試聴開始(収納SWで初回ユーザ)
    '''
    def add_datapath(self, multicast_address, datapathid, portno, ivid, pbb_isid, bvid):
        flow_mod_datas = []
        self.edge_switch.add_datapath_edge(multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas)
        # 収容スイッチに設定するフローはstartMG時と同じ
        self.container_switches[datapathid].start_mg_container(datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas)
        return flow_mod_datas;

    '''
    試聴終了(MGで最終ユーザ)/試聴終了(最終ユーザの離脱)
    '''
    def remove_mg(self, multicast_address, datapathid, portno, ivid, pbb_isid, bvid):
        flow_mod_datas = []
        self.edge_switch.remove_mg_edge(multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas)
        self.container_switches[datapathid].remove_mg_container(datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas)
        return flow_mod_datas;

    '''
    試聴終了(収納ポートで最終、同一収納SWにユーザ残存)
    '''
    def remove_port(self, multicast_address, datapathid, portno, ivid, pbb_isid, bvid):
        flow_mod_datas = []
        self.container_switches[datapathid].remove_port_container(datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas)
        return flow_mod_datas;

    '''
    試聴終了(収納SWで最終ユーザ)
    '''  
    def remove_datapath(self, multicast_address, datapathid, portno, ivid, pbb_isid, bvid):
        flow_mod_datas = []
        self.edge_switch.remove_datapath_edge(multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas)
        # 収容スイッチに設定するフローはremoveMG時と同じ
        self.container_switches[datapathid].remove_mg_container(datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas)
        return flow_mod_datas;


'''
スイッチに応じたFlowModデータ生成クラスの共通インターフェース定義
'''
class flow_mod_gen_impl(object):
    
    def __init__(self, switch_info):
        self.switch_info = switch_info
    
    
    def initialize_flows(self, ivid, pbb_isid, bvid):
        raise flow_mod_gen_excepion('Unsupported Operation')
    
    
    def start_mg_edge(self, multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')
    
    def add_datapath_edge(self, multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')
    
    def remove_mg_edge(self, multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')
    
    def remove_datapath_edge(self, multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')


    def start_mg_container(self, datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')
    
    def add_port_container(self, datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')

    def remove_mg_container(self, datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')

    def remove_port_container(self, datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')


'''
Apresia 12000 シリーズ
'''
class apresia_12k(flow_mod_gen_impl):

    TAG2PBB = 0xffff0001
    PBB2TAG = 0xffff0002
    
    def __init__(self, switch_info):
        super(apresia_12k, self).__init__(switch_info)

    def initialize_flows(self, ivid, pbb_isid, bvid):
        flow_mod_datas = []
        
        datapathid = self.switch_info['datapathid']
        
        if self.switch_info['sw_name'] == 'esw':

            edge_router_port = self.switch_info['edge_router_port']
            mld_port = self.switch_info['mld_port']
            container_sw_ports = self.switch_info['container_sw_ports']
  
  
            # table 0 エッジルータ(in_port=物理ポート2)からのMLD QueryのパケットIN
            table_id = 0
            priority = PRIORITY_NORMAL
            match = parser.OFPMatch(in_port=edge_router_port,
                                    eth_type=ether.ETH_TYPE_IPV6,
                                    ip_proto=inet.IPPROTO_ICMPV6,
                                    icmpv6_type=icmpv6.MLD_LISTENER_QUERY)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                    match=match, instructions=inst))
            
            # table 0 コントローラー(in_port=物理ポート1)からエッジルータ(in_port=物理ポート2)へMLDv2 ReportのパケットOUT
            table_id = 0
            priority = PRIORITY_NORMAL
            match = parser.OFPMatch(in_port=mld_port,
                                    eth_type=ether.ETH_TYPE_IPV6,
                                    ip_proto=inet.IPPROTO_ICMPV6,
                                    icmpv6_type=icmpv6.MLDV2_LISTENER_REPORT)
            actions = [parser.OFPActionOutput(port=edge_router_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                    match=match, instructions=inst))
    
            # table 3 コントローラからのMLD Queryを収容スイッチへ(PBBカプセル化)
            table_id = 3
            priority = PRIORITY_NORMAL
            match = parser.OFPMatch(in_port=apresia_12k.TAG2PBB,
                                    vlan_vid=ivid)
            actions = [OFPActionPopVlan(),
                       OFPActionPushPbb(ethertype=ether.ETH_TYPE_8021AH),
                       OFPActionSetField(pbb_isid=pbb_isid),
                       OFPActionSetField(eth_dst='00:00:00:00:00:00'),
                       OFPActionSetField(eth_src=self.switch_info['sw_bmac']),
                       OFPActionPushVlan(ethertype=ether.ETH_TYPE_8021AD),
                       OFPActionSetField(vlan_vid=bvid),
                       parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                    match=match, instructions=inst))
            
            # table 4 コントローラからのMLD Queryを収容スイッチへ(PBB出力ポート側)
            for container_sw_port in container_sw_ports.values():
                table_id = 4
                priority = PRIORITY_NORMAL
                match = parser.OFPMatch(in_port=self.logical_port_pbb(container_sw_port),
                                        vlan_vid=ivid)
                actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                     actions)]
                flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                        match=match, instructions=inst))

        else:
            
            edge_switch_port = self.switch_info['edge_switch_port']
            olt_ports = self.switch_info['olt_ports']
            
            # table 0 端末(OLT)(in_port=*)からのMLDv2 ReportのパケットIN
            table_id = 0
            priority = PRIORITY_NORMAL
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6,
                                    ip_proto=inet.IPPROTO_ICMPV6,
                                    icmpv6_type=icmpv6.MLDV2_LISTENER_REPORT)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                    match=match, instructions=inst))
            
            # table 4 エッジスイッチ(PBB)からのMLD Queryを端末(OLT)へ(PBB受信ポート側)
            table_id = 4
            priority = PRIORITY_NORMAL
            match = parser.OFPMatch(in_port=self.logical_port_pbb(edge_switch_port),
                                    vlan_vid=ivid)
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                    match=match, instructions=inst))
    
            # table 3 エッジスイッチ(PBB)からのMLD Queryを端末(OLT)へ(PBBデカプセル化)
            table_id = 3
            priority = PRIORITY_NORMAL
            match = parser.OFPMatch(in_port=apresia_12k.PBB2TAG,
                                    # PBBデカプセル時のBVIDは省略可
                                    eth_type=ether.ETH_TYPE_8021AH,
                                    pbb_isid=pbb_isid,
                                    eth_dst=self.switch_info['sw_bmac'])
            actions = [OFPActionPopVlan(),
                       OFPActionPopPbb(),
                       OFPActionPushVlan(ethertype=ether.ETH_TYPE_8021Q),
                       OFPActionSetField(vlan_vid=ivid),
                       parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                    match=match, instructions=inst))
            
            # table 4 エッジスイッチ(PBB)からのMLD Queryを端末(OLT)へ(Untag出力ポート側)
            for olt_port in olt_ports:
                table_id = 4
                priority = PRIORITY_LOW
                match = parser.OFPMatch(in_port=self.logical_port_untag(olt_port),
                                        vlan_vid=ivid)
                actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                     actions)]
                flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                        match=match, instructions=inst))
        
        return flow_mod_datas

    def start_mg_edge(self, multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas):

        edge_router_port = self.switch_info['edge_router_port']
        container_sw_ports = self.switch_info['container_sw_ports']
        
        table_id = 2 
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=edge_router_port,
                                # IPマルチキャスト一時内部VIDは省略
                                eth_type=ether.ETH_TYPE_IPV6,
                                ipv6_dst=multicast_address)
        actions = [OFPActionSetField(vlan_vid=ivid),
                   parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                            match=match, instructions=inst))

        table_id = 3
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=apresia_12k.TAG2PBB,
                                pbb_isid=ivid)
        actions = [OFPActionPopVlan(),
                   OFPActionPushPbb(ethertype=ether.ETH_TYPE_8021AH),
                   OFPActionSetField(vlan_vid=apresia_12k.MDL_QUERY_VLAN_VID),
                   OFPActionSetField(pbb_isid=pbb_isid),
                   OFPActionSetField(eth_dst='00:00:00:00:00:00'),
                   OFPActionSetField(eth_src=self.switch_info['sw_bmac']),
                   OFPActionPushVlan(ethertype=ether.ETH_TYPE_8021AD),
                   OFPActionSetField(vlan_vid=bvid),
                   parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                            match=match, instructions=inst))

        table_id = 4
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=self.logical_port_pbb(container_sw_ports[str(datapathid)]),
                                vlan_vid=ivid)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                                match=match, instructions=inst))

        return flow_mod_datas

    def add_datapath_edge(self, multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')
    
    def remove_mg_edge(self, multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas):
        
        edge_router_port = self.switch_info['edge_router_port']
        container_sw_ports = self.switch_info['container_sw_ports']
        
        table_id = 2 
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=edge_router_port,
                                # IPマルチキャスト一時内部VIDは省略
                                eth_type=ether.ETH_TYPE_IPV6,
                                ipv6_dst=multicast_address)
        inst = []
        flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                            match=match, instructions=inst))
        table_id = 3
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=apresia_12k.TAG2PBB,
                                pbb_isid=ivid)
        actions = [OFPActionPopVlan(),
                   OFPActionPushPbb(ethertype=ether.ETH_TYPE_8021AH),
                   OFPActionSetField(vlan_vid=apresia_12k.MDL_QUERY_VLAN_VID),
                   OFPActionSetField(pbb_isid=pbb_isid),
                   OFPActionSetField(eth_dst='00:00:00:00:00:00'),
                   OFPActionSetField(eth_src=self.switch_info['sw_bmac']),
                   OFPActionPushVlan(ethertype=ether.ETH_TYPE_8021AD),
                   OFPActionSetField(vlan_vid=bvid),
                   parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                            match=match, instructions=inst))        
                
        for container_sw_port in container_sw_ports:
            table_id = 4
            priority = PRIORITY_NORMAL
            match = parser.OFPMatch(in_port=self.logical_port_pbb(container_sw_port),
                                    vlan_vid=ivid)
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                                match=match, instructions=inst))
            
        return flow_mod_datas
    
    def remove_datapath_edge(self, multicast_address, datapathid, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')


    def start_mg_container(self, datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas):
        
        edge_switch_port = self.switch_info['edge_switch_port']
        
        table_id = 4
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=self.logical_port_pbb(edge_switch_port),
                                vlan_vid=ivid)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                            match=match, instructions=inst))

        table_id = 3
        priority = PRIORITY_NORMAL
        match = parser.OFPMatch(in_port=apresia_12k.PBB2TAG,
                                # PBBデカプセル時のBVIDは省略可
                                eth_type=ether.ETH_TYPE_8021AH,
                                pbb_isid=pbb_isid,
                                eth_dst=self.switch_info['sw_bmac'])
        actions = [OFPActionPopVlan(),
                   OFPActionPopPbb(),
                   OFPActionPushVlan(ethertype=ether.ETH_TYPE_8021Q),
                   OFPActionSetField(vlan_vid=ivid),
                   parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                            match=match, instructions=inst))
        
        table_id = 4
        priority = PRIORITY_LOW
        match = parser.OFPMatch(in_port=self.logical_port_untag(portno),
                                vlan_vid=ivid)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        flow_mod_datas.append(flow_mod_data(datapathid=datapathid, table_id=table_id, priority=priority,
                                                match=match, instructions=inst))

        return flow_mod_datas
    
    def add_port_container(self, datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')

    def remove_mg_container(self, datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')

    def remove_port_container(self, datapathid, portno, ivid, pbb_isid, bvid, flow_mod_datas):
        raise flow_mod_gen_excepion('Unsupported Operation')

    def logical_port_untag(self, portno):
        return 0x00000000 | portno

    def logical_port_tag(self, portno):
        return 0x01000000 | portno

    def logical_port_pbb(self, portno):
        return 0x02000000 | portno


'''
Apresia 26000 シリーズ
'''
class apresia_26k(flow_mod_gen_impl):
    pass


'''
FlowModジェネレータの例外クラス
'''
class flow_mod_gen_excepion(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

