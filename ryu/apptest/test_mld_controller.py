# coding: utf-8
# nose install
# >sudo pip install nose
# coverage install
# >sudo pip install coverage
# mox install
# >sudo pip install mox
#
# ■nosetestsによる実行
# nosetests test_mld_controller.py
# nosetests -v test_mld_controller.py
# nosetests -s test_mld_controller.py
# nosetests -v --with-coverage test_mld_controller.py
# ■coverage関連
# coverage erase（統計データの初期化)
# coverage run test_mld_controller.py（テストコードの実行/計測)
# coverage report（カバレッジの計測結果の表示)
# coverage html（HTMLレポート作成)

import os
import logging
import sys
import unittest
import mox
import cPickle
import zmq
from nose.tools import *

from ryu.app.mld_controller import mld_controller

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

from ryu.lib.packet.packet import Packet

from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.ofproto import ether, inet
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from nose.plugins.attrib import attr

from ryu.ofproto.ofproto_v1_3_parser import OFPPacketIn, OFPMatch

from common.zmq_dispatch import dispatch
from common.zmq_dispatch import flow_mod_data
from common.mld_const import mld_const
from common.read_json import read_json

logger = logging.getLogger(__name__)

HOST_IPADDR1 = "192.168.0.1"
HOST_MACADDR1 = "52:54:00:75:4e:57"
HOST_IPADDR2 = "192.168.1.1"
HOST_MACADDR2 = "52:54:00:0b:d0:48"
ROUTER_IPADDR1 = "192.168.0.10"
ROUTER_IPADDR2 = "192.168.1.10"
ROUTER_MACADDR1 = "00:00:00:00:00:01"
ROUTER_MACADDR2 = "00:00:00:00:00:02"
ROUTER_PORT1 = 1
ROUTER_PORT2 = 2

IPC = "ipc://"
SEND_FILE_PATH = "/tmp/feeds/test/ut"
RECV_FILE_PATH = "/tmp/feeds/test/ut"


class _Datapath(object):
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def send_msg(self, msg):
        pass


class test_mld_controller():
#class test_mld_controller(unittest.TestCase):
    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    MULTICAST_SERVICE_INFO = os.path.normpath(
        os.path.join(BASEPATH, "../../mld/app/multicast_service_info.csv"))
    ADDRESS_INFO = os.path.normpath(
        os.path.join(BASEPATH, "../../mld/app/address_info.csv"))
    addressinfo = []

    logger.debug(BASEPATH)
    logger.debug(MULTICAST_SERVICE_INFO)
    logger.debug(ADDRESS_INFO)

    # このクラスのテストケースを実行する前に１度だけ実行する
    @classmethod
    def setup_class(clazz):
        clazz.mocker = mox.Mox()
        logger.debug("setup")
        clazz.mld_ctrl = mld_controller()

        for line in open(clazz.ADDRESS_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                columns = list(line[:-1].split(","))
                for column in columns:
                    clazz.addressinfo.append(column)

    # このクラスのテストケースをすべて実行した後に１度だけ実行する
    @classmethod
    def teardown_class(clazz):
        logger.debug("teardown")

#    @attr(do=True)
    def test_cretate_scoket001(self):
        logger.debug("test_cretate_scoket001")
        # mld_controller.cretate_scoket(self, sendpath, recvpath):
        send_file_path = SEND_FILE_PATH + "/ryu-mld-createsocket"
        recv_file_path = RECV_FILE_PATH + "/mld-ryu-createsocket"

        send_path = IPC + send_file_path
        recv_path = IPC + recv_file_path

        # CHECK TMP FILE(SEND)
        self.mld_ctrl.check_exists_tmp(send_file_path)
        # CHECK TMP FILE(RECV)
        self.mld_ctrl.check_exists_tmp(recv_file_path)

        result = self.mld_ctrl.cretate_scoket(send_path, recv_path)

        os.remove(send_file_path)
        os.remove(recv_file_path)

    def test_analyse_receive_packet001(self):
        logger.debug("test_analyse_receive_packet001")
        # mld_controller.analyse_receive_packet(self, recvpkt):

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        flowmoddata = flow_mod_data(datapathid=datapath.id,
                                    table_id=0, priority=0, match=0,
                                    instructions=[],
                                    command=ofproto_v1_3.OFPFC_ADD,
                                    out_port=0, out_group=0)

        actions = [ofproto_v1_3_parser.OFPActionOutput(ofproto_v1_3.OFPP_NORMAL)]
        instructions = [ofproto_v1_3_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS,actions)]
        ofp_match = ofproto_v1_3_parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6,ip_proto=inet.IPPROTO_ICMPV6)

        flowmoddata.instructions = instructions
        flowmoddata.match = ofp_match
        flowmoddatalist = []
        flowmoddatalist.append(flowmoddata)

        dispatch_ = dispatch(type_=mld_const.CON_FLOW_MOD,
                                datapathid=datapath.id,
                                data=flowmoddatalist)

        packet = dispatch_

        result = self.mld_ctrl.analyse_receive_packet(packet)

    def test_analyse_receive_packet002(self):
        logger.debug("test_analyse_receive_packet002")
        # mld_controller.analyse_receive_packet(self, recvpkt):

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        dispatch_ = dispatch(type_=mld_const.CON_PACKET_OUT,
                                datapathid=datapath.id)

        packet = dispatch_

        result = self.mld_ctrl.analyse_receive_packet(packet)

    def test_analyse_receive_packet003(self):
        logger.debug("test_analyse_receive_packet003")
        # mld_controller.analyse_receive_packet(self, recvpkt):

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        dispatch_ = dispatch(type_=99,
                                datapathid=datapath.id)

        packet = dispatch_

        result = self.mld_ctrl.analyse_receive_packet(packet)

    def test_get_msgbase001(self):
        # mld_controller.get_msgbase(self, datapathid)
        logger.debug("test_get_msgbase001")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        result = self.mld_ctrl.get_msgbase(datapath.id)

        eq_(result, None)

    def test_get_msgbase002(self):
        # mld_controller.get_msgbase(self, datapathid)
        logger.debug("test_get_msgbase002")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        result = self.mld_ctrl.get_msgbase(datapath.id)
        eq_(result, None)

    def test_create_flow_mod001(self):
        # mld_controller.create_flow_mod(self, datapath, flowmoddata):
        logger.debug("test_create_flow_mod001")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        flowmoddata = flow_mod_data(datapathid=datapath.id,
                                    table_id=0, priority=0, match=0,
                                    instructions=[],
                                    command=ofproto_v1_3.OFPFC_ADD,
                                    out_port=0, out_group=0)

        actions = [ofproto_v1_3_parser.OFPActionOutput(ofproto_v1_3.OFPP_NORMAL)]
        instructions = [ofproto_v1_3_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS,actions)]
        ofp_match = ofproto_v1_3_parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6,ip_proto=inet.IPPROTO_ICMPV6)

        flowmoddata.instructions = instructions
        flowmoddata.match = ofp_match

        self.mld_ctrl.create_flow_mod(datapath, flowmoddata)

    def test_send_to_mld001(self):
        # mld_controller.send_to_mld
        logger.debug("test_send_to_mld001")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        dispatch_ = dispatch(type_=mld_const.CON_SWITCH_FEATURE,
                                datapathid=datapath.id)

        self.mld_ctrl.send_to_mld(dispatch_)

    def test_receive_from_mld001(self):
        # mld_controller.receive_from_mld
        logger.debug("test_receive_from_mld001")

    def test_send_msg_to_flowmod001(self):
        # mld_controller.send_msg_to_flowmod(self, msgbase, flowmod):
        logger.debug("test_send_msg_to_flowmod001")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)

        flowmoddata = flow_mod_data(datapathid=datapath.id,
                                    table_id=0, priority=0, match=0,
                                    instructions=[],
                                    command=ofproto_v1_3.OFPFC_ADD,
                                    out_port=0, out_group=0)

        actions = [ofproto_v1_3_parser.OFPActionOutput(ofproto_v1_3.OFPP_NORMAL)]
        instructions = [ofproto_v1_3_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS,actions)]
        ofp_match = ofproto_v1_3_parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6,ip_proto=inet.IPPROTO_ICMPV6)

        flowmoddata.instructions = instructions
        flowmoddata.match = ofp_match

        flowmod = self.mld_ctrl.create_flow_mod(datapath, flowmoddata)

        self.mld_ctrl.send_msg_to_flowmod(ev.msg, flowmod)

    def test_send_msg_to_barrier_request001(self):
        # mld_controller.send_msg_to_barrier_request(self, msgbase):
        logger.debug("test_send_msg_to_barrier_request001")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)

        self.mld_ctrl.send_msg_to_barrier_request(ev.msg)

    def test_send_msg_to_packetout001(self):
        # mld_controller.send_msg_to_packetout(self, msgbase, packetout):
        logger.debug("test_send_msg_to_packetout001")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)

        packetoutdata = ""
        self.mld_ctrl.send_msg_to_packetout(ev.msg, packetoutdata)

    def test_check_exists_tmp001(self):
        # mld_controller.check_exists_tmp(self, filename)
        logger.debug("test_check_exists_tmp001")
        """
        zmqで使用するipcのtmpファイルを格納するディレクトリの存在チェック
        条件：ディレクトが存在しない
        結果：引数に渡したディレクトリ、ファイル名のディレクトリ、ファイルを作成する
        """
        send_file_path = SEND_FILE_PATH + "/ryu-mld-test"
        self.mld_ctrl.check_exists_tmp(send_file_path)

    def test_check_exists_tmp002(self):
        # mld_controller.check_exists_tmp(self, filename)
        logger.debug("test_check_exists_tmp002")
        """
        zmqで使用するipcのtmpファイルの存在チェック
        条件：tmpファイルが存在する
        結果：return
        """
        send_file_path = SEND_FILE_PATH + "/ryu-mld-test"
        self.mld_ctrl.check_exists_tmp(send_file_path)
        
        # 後続試験のため、作成したファイルを削除
        os.remove(send_file_path)

    def test_check_exists_tmp003(self):
        # mld_controller.check_exists_tmp(self, filename)
        logger.debug("test_check_exists_tmp003")
        """
        zmqで使用するipcのtmpファイルの存在チェック
        条件：tmpファイルが存在しない
        結果：引数に渡したファイル名のファイルを作成する
        """
        send_file_path = SEND_FILE_PATH + "/ryu-mld-test"
        self.mld_ctrl.check_exists_tmp(send_file_path)
        os.remove(send_file_path)
        os.rmdir(SEND_FILE_PATH)

    def test_switch_features_handler_001(self):
        # mld_controller._switch_features_handler
        logger.debug("test_switch_features_handler001")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)
        result = self.mld_ctrl._switch_features_handler(ev)
#        self.assertEqual(result, 0)

    def test_switch_features_handler_002(self):
        # mld_controller._switch_features_handler
        logger.debug("test_switch_features_handler002")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        self.mld_ctrl.dic_msg[datapath.id] = "aaa"

        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)
        result = self.mld_ctrl._switch_features_handler(ev)
#        self.assertEqual(result, 0)

    def test_barrier_reply_handler001(self):
        # mld_controller._barrier_reply_handler(self, ev)
        logger.debug("test_barrier_reply_handler001")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        featuresRequest = ofproto_v1_3_parser.OFPBarrierReply(datapath)
        ev = ofp_event.EventOFPBarrierReply(featuresRequest)
        result = self.mld_ctrl._barrier_reply_handler(ev)
#         result = controller._barrier_reply_handler(ev)

    def test_packet_in_handler_Success_001(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Success_001")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        """
        dispatch_ = dispatch(type_=mld_const.CON_PACKET_IN,
                               datapathid=msg.datapath.id,
                               cid=pkt_vlan.vid,
                               in_port=msg.match["in_port"],
                               data=pkt_icmpv6)
        """
        dstMac = "ff:ff:ff:ff:ff:ff"
        srcMac = HOST_MACADDR1
        srcIp = HOST_IPADDR1
        dstIp = ROUTER_IPADDR1
        targetMac = dstMac
        targetIp = dstIp

        packet = Packet()
        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
        packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.MLD_LISTENER_QUERY,
                                          data=icmpv6.mldv2_query()))
        packet.serialize()

        packetIn = OFPPacketIn(datapath, match=OFPMatch(in_port=1), data=buffer(packet.data))

        ev = ofp_event.EventOFPPacketIn(packetIn)

        result = self.mld_ctrl._packet_in_handler(ev)

    def test_packet_in_handler_failure_001(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_failure_001")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        dstMac = "ff:ff:ff:ff:ff:ff"
        srcMac = HOST_MACADDR1
        srcIp = HOST_IPADDR1
        dstIp = ROUTER_IPADDR1
        targetMac = dstMac
        targetIp = dstIp

        packet = Packet()
#        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
        packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.MLD_LISTENER_QUERY,
                                          data=icmpv6.mldv2_query()))
        packet.serialize()

        packetIn = OFPPacketIn(datapath, match=OFPMatch(in_port=1), data=buffer(packet.data))

        ev = ofp_event.EventOFPPacketIn(packetIn)

        result = self.mld_ctrl._packet_in_handler(ev)

    def test_packet_in_handler_failure_002(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_failure_002")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        dstMac = "ff:ff:ff:ff:ff:ff"
        srcMac = HOST_MACADDR1
        srcIp = HOST_IPADDR1
        dstIp = ROUTER_IPADDR1
        targetMac = dstMac
        targetIp = dstIp

        packet = Packet()
        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
#       packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.MLD_LISTENER_QUERY,
                                          data=icmpv6.mldv2_query()))
        packet.serialize()

        packetIn = OFPPacketIn(datapath, match=OFPMatch(in_port=1), data=buffer(packet.data))

        ev = ofp_event.EventOFPPacketIn(packetIn)

        result = self.mld_ctrl._packet_in_handler(ev)

    def test_packet_in_handler_failure_003(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_failure_003")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        dstMac = "ff:ff:ff:ff:ff:ff"
        srcMac = HOST_MACADDR1
        srcIp = HOST_IPADDR1
        dstIp = ROUTER_IPADDR1
        targetMac = dstMac
        targetIp = dstIp

        packet = Packet()
        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
        packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
#        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
#        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.MLD_LISTENER_QUERY,
#                                          data=icmpv6.mldv2_query()))
        packet.serialize()

        packetIn = OFPPacketIn(datapath, match=OFPMatch(in_port=1), data=buffer(packet.data))

        ev = ofp_event.EventOFPPacketIn(packetIn)

        result = self.mld_ctrl._packet_in_handler(ev)

    def test_packet_in_handler_failure_004(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_failure_004")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        dstMac = "ff:ff:ff:ff:ff:ff"
        srcMac = HOST_MACADDR1
        srcIp = HOST_IPADDR1
        dstIp = ROUTER_IPADDR1
        targetMac = dstMac
        targetIp = dstIp

        packet = Packet()
        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
        packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.ICMPV6_ECHO_REQUEST,
                                          data=icmpv6.mldv2_query()))
        packet.serialize()

        packetIn = OFPPacketIn(datapath, match=OFPMatch(in_port=1), data=buffer(packet.data))

        ev = ofp_event.EventOFPPacketIn(packetIn)

        result = self.mld_ctrl._packet_in_handler(ev)

    def test_packet_in_handler_failure_005(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_failure_004")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        dstMac = "ff:ff:ff:ff:ff:ff"
        srcMac = HOST_MACADDR1
        srcIp = HOST_IPADDR1
        dstIp = ROUTER_IPADDR1
        targetMac = dstMac
        targetIp = dstIp

        packet = Packet()
        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
        packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.MLDV2_LISTENER_REPORT,
                                          data=icmpv6.mldv2_report()))
        packet.serialize()

        packetIn = OFPPacketIn(datapath, match=OFPMatch(in_port=1), data=buffer(packet.data))

        ev = ofp_event.EventOFPPacketIn(packetIn)

        result = self.mld_ctrl._packet_in_handler(ev)

    def test_packet_in_handler_failure_006(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_failure_004")

        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1

        dstMac = "ff:ff:ff:ff:ff:ff"
        srcMac = HOST_MACADDR1
        srcIp = HOST_IPADDR1
        dstIp = ROUTER_IPADDR1
        targetMac = dstMac
        targetIp = dstIp

        record = icmpv6.mldv2_report_group()
        record.type_ = icmpv6.ICMPV6_MAXTYPE
        records = []
        records.append(record)

        mldv2_report_ = icmpv6.mldv2_report()
        mldv2_report_.records = records

        packet = Packet()
        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
        packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.MLDV2_LISTENER_REPORT,
                                          data=mldv2_report_))
        packet.serialize()

        packetIn = OFPPacketIn(datapath, match=OFPMatch(in_port=1), data=buffer(packet.data))

        ev = ofp_event.EventOFPPacketIn(packetIn)

        result = self.mld_ctrl._packet_in_handler(ev)

if __name__ == '__main__':
    unittest.main()
