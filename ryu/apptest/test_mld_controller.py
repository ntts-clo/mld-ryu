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
import pdb
import nose
import os
import logging
import logging.config
import sys
import unittest
from mox import Mox, UnknownMethodCallError, ExpectedMethodCallsError,\
    UnexpectedMethodCallError, IsA, StrContains

import cPickle
import zmq
from nose.tools import assert_equal
from nose.tools import assert_not_equal
from nose.tools import assert_raises
from nose.tools import eq_
from nose.tools import ok_

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
APP_PATH = DIR_PATH + "/../app/"
sys.path.append(APP_PATH)
import mld_controller

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

from ryu.lib.packet.packet import Packet

from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.ofproto import ether, inet
from ryu.controller import dpset, ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from nose.plugins.attrib import attr
from ryu.ofproto.ofproto_v1_3_parser import OFPPacketIn, OFPMatch

COMMON_PATH = DIR_PATH + "/../../common/"
sys.path.append(COMMON_PATH)
from icmpv6_extend import icmpv6_extend
from zmq_dispatch import dispatch
from zmq_dispatch import flow_mod_data, packet_out_data
from read_json import read_json
from ryu.lib import hub
hub.patch()

import mld_const

logging.config.fileConfig(COMMON_PATH + mld_const.RYU_LOG_CONF)
logger = logging.getLogger(__name__)

# OpenFlowのバージョン
OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
# Socketタイプチェック用定数
CHECK_ZMQ_TYPE_IPC = "ipc"
CHECK_ZMQ_TYPE_TCP = "tcp"
CHECK_URL_IPC = "ipc://"
CHECK_URL_TCP = "tcp://"

# 設定ファイルの定義名
SETTING = "settings"
CHECK_VLAN_FLG = "check_vlan_flg"
#OFC_ZMQ_URL = "ofc_zmq_url"
#OFC_ZMQ_SEND = "ofc_zmq_send"
#OFC_ZMQ_RECV = "ofc_zmq_recv"
ZMQ_TYPE = "zmq_type"
ZMQ_IPC = "zmq_ipc"
ZMQ_TCP = "zmq_tcp"
ZMQ_PUB = "mld_zmq"
ZMQ_SUB = "ofc_zmq"
MLD_SERVER_IP = "mld_server_ip"

# VLANチェックフラグ用定数
CHECK_VLAN_FLG = True
# ZMQ用定数
URL_DELIMIT = "://"
PORT_DELIMIT = ":"
SEND_IP = "0.0.0.0"

# 設定ファイルの定義名


MC_ADDR1 = "ff38::1:1"
SERVER_IP1 = "2001::1:20"
MC_ADDR2 = "ff38::1:2"
SERVER_IP2 = "2001::1:20"
SRC_MC_ADDR = "d4:3d:7e:4a:43:fd"
DST_MC_ADDR = "33:33:fe:4a:43:fd"
SRC_IP = "e80::d63d:7eff:fe4a:43fd"
DST_IP = "FF02::1"

#HOST_IPADDR1 = "fe80::200:ff:fe00:1"
#HOST_MACADDR1 = "00:00:00:00:00:01"
HOST_IPADDR1 = "fe80::d63d:7eff:fe4a:460c"
HOST_MACADDR1 = "d4:3d:7e:4a:46:0c"
HOST_IPADDR2 = "fe80::200:ff:fe00:2"
HOST_MACADDR2 = "00:00:00:00:00:02"

SEND_FILE_PATH = "/tmp/feeds/test/ut"
RECV_FILE_PATH = "/tmp/feeds/test/ut"
SEND_IP = "0.0.0.0:7002"
RECV_IP = "192.168.5.11:7002"


class _Datapath(object):
    """
    DummyDatapath生成クラス
    """

    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def send_msg(self, msg):
        pass


class test_mld_controller():
#class test_mld_controller(unittest.TestCase):
    """
    mld_controller testクラス
    """

    # 各設定ファイルの読み込み
    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    MULTICAST_SERVICE_INFO = os.path.normpath(
        os.path.join(BASEPATH, COMMON_PATH + "multicast_service_info.csv"))

    logger.debug(BASEPATH)
    logger.debug(MULTICAST_SERVICE_INFO)

    # このクラスのテストケースを実行する前に１度だけ実行する
    @classmethod
    def setup_class(cls):
        logger.debug("setup_class")

        config = read_json(COMMON_PATH + mld_const.CONF_FILE)
        cls.config = config.data["settings"]
        cls.config_zmq_ipc = config.data[ZMQ_IPC]
        cls.config_zmq_tcp = config.data[ZMQ_TCP]

        mc_info = read_json(COMMON_PATH + mld_const.MULTICAST_INFO)
        cls.mc_info_list = mc_info.data["mc_info"]
        """
        dpset_ins = dpset.DPSet()
        kwargs = {}
        kwargs['dpset'] = dpset_ins
        cls.mld_ctrl = mld_controller.mld_controller(**kwargs)
        """
    # このクラスのテストケースをすべて実行した後に１度だけ実行する
    @classmethod
    def teardown_class(clazz):
        logger.debug("teardown")

    def setup(self):
        self.mocker = Mox()

        dpset_ins = dpset.DPSet()
        kwargs = {}
        kwargs['dpset'] = dpset_ins
        self.mld_ctrl = mld_controller.mld_controller(**kwargs)

        # 設定値の初期化
        self.mld_ctrl.config = self.config

        # zmq設定情報の読み込み
        self.zmq_pub = None
        self.zmq_sub = None

        # CHECK zmq用URL
        if self.mld_ctrl.check_zmq_type(self.config[ZMQ_TYPE]):
            # IPCによるSoket設定の読み込み
            self.zmq_pub = self.config_zmq_ipc[ZMQ_PUB]
            self.zmq_sub = self.config_zmq_ipc[ZMQ_SUB]
            # CHECK TMP FILE(SEND)
            self.mld_ctrl.check_exists_tmp(self.zmq_pub)
            # CHECK TMP FILE(RECV)
            self.mld_ctrl.check_exists_tmp(self.zmq_sub)
        else:
            # TCPによるSoket設定の読み込み
            self.zmq_sub = self.config_zmq_tcp[MLD_SERVER_IP]
            self.zmq_sub_list = self.zmq_sub.split(PORT_DELIMIT)
            # zmq_subのポート設定を取得し、zmq_pubのIPアドレスに付与
            self.zmq_pub = SEND_IP + PORT_DELIMIT + self.zmq_sub_list[1]

    def tearDown(self):
        # StubOutWithMoc()を呼んだ後に必要。常に呼んでおけば安心
        self.mocker.UnsetStubs()

    def test_create_socket_Success001(self):
        logger.debug("test_create_socket_Success001")
        """
        概要：zmqの送受信で使用するsocketを生成
        条件：SEND用・RECV用のipcのtmpファイルパスを指定する
        結果：SEND用・RECV用のsocketが生成されること
        """
        #【前処理】
        zmq_url = "ipc://"
        send_file_path = SEND_FILE_PATH + "/ryu-mld-createsocket"
        recv_file_path = RECV_FILE_PATH + "/mld-ryu-createsocket"

        send_path = zmq_url + send_file_path
        recv_path = zmq_url + recv_file_path

        # CHECK TMP FILE(SEND)
        self.mld_ctrl.check_exists_tmp(send_file_path)
        # CHECK TMP FILE(RECV)
        self.mld_ctrl.check_exists_tmp(recv_file_path)

        #【実行】
        self.mld_ctrl.create_socket(send_path, recv_path)

        #【結果】
        ok_(self.mld_ctrl.send_sock)
        ok_(self.mld_ctrl.recv_sock)

        #【後処理】 作成したfilepathを削除
        os.remove(send_file_path)
        os.remove(recv_file_path)

    def test_create_socket_Success002(self):
        logger.debug("test_create_socket_Success002")
        """
        概要：zmqの送受信で使用するsocketを生成
        条件：SEND用・RECV用のtcpのipを指定する
        結果：SEND用・RECV用のsocketが生成されること
        """
        #【前処理】
        zmq_url = "tcp://"
        send_ip_path = SEND_IP
        recv_ip_path = RECV_IP

        send_path = zmq_url + send_ip_path
        recv_path = zmq_url + recv_ip_path

        #【実行】
        self.mld_ctrl.create_socket(send_path, recv_path)

        #【結果】
        ok_(self.mld_ctrl.send_sock)
        ok_(self.mld_ctrl.recv_sock)

    def test_analyse_receive_packet_Success001(self):
        logger.debug("test_analyse_receive_packet_Success001")
        # mld_controller.analyse_receive_packet(self, recvpkt):
        """
        概要：zmqにてmld_plocessより受信したpacketを検証し処理を振り分ける
        条件：正常に動作するであろうDummyのPACKET_OUTデータを設定し、実行する
        結果：戻り値にFALSEが設定されていないこと
        """
        #【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999

        # dict_msgの作成
        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)
        ev.msg.version=4
#        self.mld_ctrl.dict_msg[datapath.id] = ev.msg
        #dpset.set_ev_cls(ev, datapath)
        """
        dpset_ins = dpset.DPSet()
        dpset_ins.switch_features_handler(ev)
        """
        #dpset.DPSet.send_request(ev)
        #dpset.DPSet.register_handler(ev)
        # DummyPACKET_OUTのデータを作成
        # ETHER
        eth = ethernet.ethernet(
            ethertype=ether.ETH_TYPE_8021Q,
            src=SRC_MC_ADDR, dst=DST_MC_ADDR)

        # VLAN
        vln = vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6)
        #vln = vlan.vlan(vid=self.config["c_tag_id"],
        #ethertype=ether.ETH_TYPE_IPV6)

        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6, data=[
            ipv6.option(type_=5, len_=2, data="\x00\x00"),
            ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(
            src=SRC_IP, dst=DST_IP,
            hop_limit=1, nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

        mld = icmpv6.mldv2_query(
            address=str(MC_ADDR1),
            srcs=[str(SERVER_IP1)] if SERVER_IP1 else None,
            maxresp=10000, qrv=2,
            qqic=10)

        # MLDV2
        if type(mld) == icmpv6.mldv2_query:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLD_LISTENER_QUERY, data=mld)

        elif type(mld) == icmpv6.mldv2_report:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        # ether - vlan - ipv6 - icmpv6 ( - mldv2 )
        sendpkt = eth / vln / ip6 / icmp6
        sendpkt.serialize()
        packetoutdata = sendpkt

        switches = read_json(COMMON_PATH + "switch_info.json")
        self.switch_mld_info = switches.data["switch_mld_info"]
        self.switch_mc_info = switches.data["switch_mc_info"]
        self.switches = switches.data["switches"]
        self.edge_switch = self.switches[0]

        actions = [ofproto_v1_3_parser.OFPActionOutput(
            port=self.edge_switch["edge_router_port"])]

        packetdata = packet_out_data(datapathid=datapath.id,
                                in_port=ofproto_v1_3.OFPP_CONTROLLER,
                                buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                                actions=actions,
                                data=packetoutdata)

        packet = dispatch(type_=mld_const.CON_PACKET_OUT,
                                datapathid=datapath.id,
                                data=packetdata)

        # モック作成
        self.mocker.StubOutWithMock(self.mld_ctrl, "send_msg_to_packetout")
        self.mld_ctrl.send_msg_to_packetout(ev.msg, packet).AndReturn(0)

        #【実行】
        self.mocker.ReplayAll()
        result = self.mld_ctrl.analyse_receive_packet(packet)

        # 【結果】
        self.mocker.VerifyAll()
        logger.debug("test_analyse_receive_packet_Success001 [result] %s",
                     str(result))
        assert_not_equal(result, False)

    def test_analyse_receive_packet_Success002(self):
        logger.debug("test_analyse_receive_packet_Success002")
        # mld_controller.analyse_receive_packet(self, recvpkt):
        """
        概要：zmqにてmld_plocessより受信したpacketを検証し処理を振り分ける
        条件：正常に動作するであろうDummyのFLOW_MODデータを設定し、実行する
        結果：戻り値にFALSEが設定されていないこと
        """
        #【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 11111

        # dict_msgの作成
        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)
        #self.mld_ctrl.dict_msg[datapath.id] = ev.msg
#        dpset.DPSet.switch_features_handler(ev)
        """
        dpset_ins = dpset.DPSet()
        dpset_ins.switch_features_handler(ev)
        """
        # DummyFLOW_MODのデータを作成
        flowmoddata = flow_mod_data(datapathid=datapath.id,
                                    table_id=0, priority=0, match=0,
                                    instructions=[],
                                    command=ofproto_v1_3.OFPFC_ADD,
                                    out_port=0, out_group=0)

        actions = [ofproto_v1_3_parser.OFPActionOutput( \
                   ofproto_v1_3.OFPP_NORMAL)]
        instructions = [ofproto_v1_3_parser.OFPInstructionActions( \
                   ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
        ofp_match = ofproto_v1_3_parser.OFPMatch( \
                   eth_type=ether.ETH_TYPE_IPV6, ip_proto=inet.IPPROTO_ICMPV6)

        flowmoddata.instructions = instructions
        flowmoddata.match = ofp_match
        flowmoddatalist = []
        flowmoddatalist.append(flowmoddata)

        # dispatchにFLOW_MODのTYPEを指定し、DummyFLOW_MODのデータを設定
        packet = dispatch(type_=mld_const.CON_FLOW_MOD,
                                datapathid=datapath.id,
                                data=flowmoddatalist)

        # モック作成
        self.mocker.StubOutWithMock(self.mld_ctrl,
                                    "send_msg_to_barrier_request")
        self.mld_ctrl.send_msg_to_barrier_request(ev.msg).AndReturn(0)

        #【実行】
        self.mocker.ReplayAll()
        result = self.mld_ctrl.analyse_receive_packet(packet)

        # 【結果】
        self.mocker.VerifyAll()
        logger.debug("test_analyse_receive_packet_Success002 [result] %s",
                     str(result))
        assert_not_equal(result, False)

    def test_analyse_receive_packet_Success003(self):
        # mld_controller.analyse_receive_packet(self, recvpkt):
        logger.debug("test_analyse_receive_packet_Success003")
        """
        概要：zmqにてmld_plocessより受信したpacketを検証し処理を振り分ける
        条件：正常に動作するであろうDummyのFLOW_MODが2レコード存在する
              データを設定し、実行する
              1レコード目=正常データ
              1レコード目=dict_msgに対象のdatapathidが存在しない
        結果：戻り値にFALSEが設定されていないこと
        """
        #【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 22222

        # dict_msgの作成
        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)
        #self.mld_ctrl.dict_msg[datapath.id] = ev.msg
#        dpset.set_ev_cls(ev, datapath)
#        dpset.DPSet.switch_features_handler(ev)
        """
        dpset_ins = dpset.DPSet()
        dpset_ins.switch_features_handler(ev)
        """
        # DummyFLOW_MODのデータを作成
        flowmoddata = flow_mod_data(datapathid=datapath.id,
                                    table_id=0, priority=0, match=0,
                                    instructions=[],
                                    command=ofproto_v1_3.OFPFC_ADD,
                                    out_port=0, out_group=0)
        flowmoddata2 = flow_mod_data(datapathid=3,
                                    table_id=2, priority=2, match=2,
                                    instructions=[],
                                    command=ofproto_v1_3.OFPFC_ADD,
                                    out_port=2, out_group=2)

        actions = [ofproto_v1_3_parser.OFPActionOutput( \
                   ofproto_v1_3.OFPP_NORMAL)]
        instructions = [ofproto_v1_3_parser.OFPInstructionActions( \
                   ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
        ofp_match = ofproto_v1_3_parser.OFPMatch( \
                   eth_type=ether.ETH_TYPE_IPV6, ip_proto=inet.IPPROTO_ICMPV6)

        flowmoddata.instructions = instructions
        flowmoddata.match = ofp_match
        flowmoddatalist = []
        flowmoddatalist.append(flowmoddata)
        flowmoddatalist.append(flowmoddata2)

        # dispatchにFLOW_MODのTYPEを指定し、DummyFLOW_MODのデータを設定
        packet = dispatch(type_=mld_const.CON_FLOW_MOD,
                                datapathid=datapath.id,
                                data=flowmoddatalist)

        # モック作成
        self.mocker.StubOutWithMock(self.mld_ctrl,
                                    "send_msg_to_barrier_request")
        self.mld_ctrl.send_msg_to_barrier_request(ev.msg).AndReturn(0)

        #【実行】
        self.mocker.ReplayAll()
        result = self.mld_ctrl.analyse_receive_packet(packet)

        # 【結果】
        self.mocker.VerifyAll()
        logger.debug("test_analyse_receive_packet_Success003 [result] %s",
                     str(result))
        assert_not_equal(result, False)

    def test_analyse_receive_packet_Failure001(self):
        logger.debug("test_analyse_receive_packet_Failure001")
        # mld_controller.analyse_receive_packet(self, recvpkt):
        """
        概要：zmqにてmld_plocessより受信したpacketを検証し処理を振り分ける
        条件：dispatchのtypeに想定外の値[99]を設定し、正常に動作するであろう
              DummyのPACKET_OUTデータを設定し、実行する
        結果：戻り値にFALSEが設定されていること
        """
        #【前処理】
        # DummyDatapathの生成
        datapath = _Datapath()
        # DummyDatapathidの設定
        datapath.id = 1
        datapath.xid = 999
        # dispatchの設定
        packet = dispatch(type_=99, datapathid=datapath.id)

        #【実行】
        result = self.mld_ctrl.analyse_receive_packet(packet)

        #【結果】
        logger.debug("test_analyse_receive_packet_Failure001 [result] %s",
                     str(result))
        assert_equal(result, False)

    def test_analyse_receive_packet_Failure002(self):
        logger.debug("test_analyse_receive_packet_Failure002")
        # mld_controller.analyse_receive_packet(self, recvpkt):
        """
        概要：zmqにてmld_plocessより受信したpacketを検証し処理を振り分ける
        条件：dict_msgに対象のdatapathidが存在しない値を設定し、
              正常に動作するであろうDummyのPACKET_OUTデータを設定し、実行する
        結果：戻り値にNoneが設定されていること
        """
        #【前処理】
        # DummyDatapathの生成
        datapath = _Datapath()
        # DummyDatapathidの設定
        datapath.id = 1
        datapath.xid = 999
        # dict_msgの作成
        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)
        #self.mld_ctrl.dict_msg[2] = ev.msg
        dpset.set_ev_cls(ev, datapath)

        # DummyPACKET_OUTのデータを作成
        # ETHER
        eth = ethernet.ethernet(
            ethertype=ether.ETH_TYPE_8021Q,
            src=SRC_MC_ADDR, dst=DST_MC_ADDR)

        # VLAN
        vln = vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6)
        #vln = vlan.vlan(vid=self.config["c_tag_id"],
        #ethertype=ether.ETH_TYPE_IPV6)

        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6, data=[
            ipv6.option(type_=5, len_=2, data="\x00\x00"),
            ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(
            src=SRC_IP, dst=DST_IP,
            hop_limit=1, nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

        mld = icmpv6.mldv2_query(
            address=str(MC_ADDR1),
            srcs=[str(SERVER_IP1)] if SERVER_IP1 else None,
            maxresp=10000, qrv=2,
            qqic=10)

        # MLDV2
        if type(mld) == icmpv6.mldv2_query:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLD_LISTENER_QUERY, data=mld)

        elif type(mld) == icmpv6.mldv2_report:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        # ether - vlan - ipv6 - icmpv6 ( - mldv2 )
        sendpkt = eth / vln / ip6 / icmp6
        sendpkt.serialize()
        packetoutdata = sendpkt

        packet = dispatch(type_=mld_const.CON_PACKET_OUT,
                                datapathid=datapath.id, data=packetoutdata)

        #【実行】
        result = self.mld_ctrl.analyse_receive_packet(packet)

        #【結果】
        logger.debug("test_analyse_receive_packet_Failure002 [result] %s",
                     str(result))
        assert_equal(result, False)

    def test_analyse_receive_packet_Failure003(self):
        # mld_controller.analyse_receive_packet(self, recvpkt):
        logger.debug("test_analyse_receive_packet_Failure003")
        """
        概要：zmqにてmld_plocessより受信したpacketを検証し処理を振り分ける
        条件：例外が発生する様packetにNoneを設定し、実行する
        結果：Exceptionが発生すること
        """
        try:
            #【前処理】
            # DummyDatapathを生成
            datapath = _Datapath()
            # DummyDatapathidを設定
            datapath.id = 1
            datapath.xid = 999

            # dict_msgの作成
            featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
            ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)
            #self.mld_ctrl.dict_msg[datapath.id] = ev.msg
            dpset.set_ev_cls(ev, datapath)

            switches = read_json(COMMON_PATH + "switch_info.json")
            self.switch_mld_info = switches.data["switch_mld_info"]
            self.switch_mc_info = switches.data["switch_mc_info"]
            self.switches = switches.data["switches"]
            self.edge_switch = self.switches[0]

            packet = None

            # モック作成
            self.mocker.StubOutWithMock(self.mld_ctrl, "send_msg_to_packetout")
            self.mld_ctrl.send_msg_to_packetout(ev.msg, packet).AndReturn(0)

            #【実行】
            #self.mocker.ReplayAll()
            self.mld_ctrl.analyse_receive_packet(packet)

        except Exception as e:
            # 【結果】
            logger.debug("test_analyse_receive_packet_Failure003[Exception]%s",
                         e)
            assert_raises(Exception, e)
        return

    def test_create_flow_mod_Success001(self):
        # mld_controller.create_flow_mod(self, datapath, flowmoddata):
        logger.debug("test_create_flow_mod_Success001")
        """
        概要：flow_mld作成処理
        条件：正常に動作するであろうDummyのflowmlddataを設定し、実行する
        結果：戻り値のflow_mld_dataと、Dummyのflowmlddataが一致していること
        """
        #【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        #FlowModDataDetail
        ch_table_id = 0
        ch_command = 2
        ch_priority = 3
        ch_out_port = 4
        ch_out_group = 5

        # DummyFLOW_MODのデータを作成
        flowmoddata = flow_mod_data(datapathid=datapath.id,
                                    table_id=ch_table_id, command=ch_command,
                                    priority=ch_priority,
                                    out_port=ch_out_port,
                                    out_group=ch_out_group,
                                    match=0,
                                    instructions=[])

        ofp_match = ofproto_v1_3_parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6,
                                                 ip_proto=inet.IPPROTO_ICMPV6)
        actions = [ofproto_v1_3_parser.OFPActionOutput(
                                            ofproto_v1_3.OFPP_CONTROLLER,
                                            ofproto_v1_3.OFPCML_NO_BUFFER)]
        instructions = [ofproto_v1_3_parser.OFPInstructionActions(
                                            ofproto_v1_3.OFPIT_APPLY_ACTIONS,
                                            actions)]
        flowmoddata.match = ofp_match
        flowmoddata.instructions = instructions

        #【実行】
        result = self.mld_ctrl.create_flow_mod(datapath, flowmoddata)

        #【結果】
        # 結果確認用flowmoddata作成
        ch_match = ofproto_v1_3_parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6,
                                                ip_proto=inet.IPPROTO_ICMPV6)

        # 結果確認
        assert_equal(result.table_id, ch_table_id)
        assert_equal(result.command, ch_command)
        assert_equal(result.priority, ch_priority)
        assert_equal(result.out_port, ch_out_port)
        assert_equal(result.out_group, ch_out_group)
        assert_equal(result.match["eth_type"], ch_match["eth_type"])
        assert_equal(result.match["ip_proto"], ch_match["ip_proto"])

    def test_create_packet_out_Success001(self):
        # mld_controller.create_flow_mod(self, datapath, flowmoddata):
        logger.debug("test_create_packet_out_Success001")
        """
        概要：packet_out作成処理
        条件：正常に動作するであろうDummyのpacketoutdataを設定し、実行する
        結果：戻り値のpacketout_dataと、Dummyのpacketoutdataが一致していること
        """
        #【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999

        # dict_msgの作成
        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)
        #self.mld_ctrl.dict_msg[datapath.id] = ev.msg
        dpset.set_ev_cls(ev, datapath)

        # DummyPACKET_OUTのデータを作成
        # ETHER
        eth = ethernet.ethernet(
            ethertype=ether.ETH_TYPE_8021Q,
            src=SRC_MC_ADDR, dst=DST_MC_ADDR)

        # VLAN
        vln = vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6)
        #vln = vlan.vlan(vid=self.config["c_tag_id"],
        #ethertype=ether.ETH_TYPE_IPV6)

        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6, data=[
            ipv6.option(type_=5, len_=2, data="\x00\x00"),
            ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(
            src=SRC_IP, dst=DST_IP,
            hop_limit=1, nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

        mld = icmpv6.mldv2_query(
            address=str(MC_ADDR1),
            srcs=[str(SERVER_IP1)] if SERVER_IP1 else None,
            maxresp=10000, qrv=2,
            qqic=10)

        # MLDV2
        if type(mld) == icmpv6.mldv2_query:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLD_LISTENER_QUERY, data=mld)

        elif type(mld) == icmpv6.mldv2_report:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        # ether - vlan - ipv6 - icmpv6 ( - mldv2 )
        sendpkt = eth / vln / ip6 / icmp6
        sendpkt.serialize()
        packetoutdata = sendpkt

        switches = read_json(COMMON_PATH + "switch_info.json")
        self.switch_mld_info = switches.data["switch_mld_info"]
        self.switch_mc_info = switches.data["switch_mc_info"]
        self.switches = switches.data["switches"]
        self.edge_switch = self.switches[0]

        actions = [ofproto_v1_3_parser.OFPActionOutput(
            port=self.edge_switch["edge_router_port"])]

        packetdata = packet_out_data(datapathid=datapath.id,
                                buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                                in_port=ofproto_v1_3.OFPP_CONTROLLER,
                                actions=actions,
                                data=packetoutdata)

        #【実行】
        result = self.mld_ctrl.create_packet_out(datapath, packetdata)
        #【結果】
        logger.debug("test_create_packet_out_Success001 [result] %s",
                     result.data)
        # 結果確認用flowmoddata作成

        # 結果確認

    def test_send_to_mld_Success001(self):
        # mld_controller.send_to_mld
        logger.debug("test_send_to_mld_Success001")
        """
        概要：MLD_Process送信処理
        条件：正常に動作するであろうデータを設定し、実行する
        結果：resultがNoneであること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # dispatch_の作成
        dispatch_ = dispatch(type_=mld_const.CON_MAIN_DISPACHER,
                                datapathid=datapath.id)

        # 【実行】
        result = self.mld_ctrl.send_to_mld(dispatch_)

        # 【結果】
        logger.debug("test_send_to_mld_Success001 [result] %s", str(result))
        assert_equal(result, None)

    def test_receive_from_mld_Success001(self):
        # mld_controller.receive_from_mld
        logger.debug("test_receive_from_mld_Success001")
        """
        試験方法自体を検討する必要あり、
        まず、無限ループを止められる実装を行う必要があり。
        概要：MLD_Process受信処理
        条件：正常に動作するであろうデータを設定し、実行する
        結果：resultがNoneであること
        """

        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        self.mld_ctrl.loop_flg = True

        config = read_json(COMMON_PATH + mld_const.CONF_FILE)
        self.config = config.data["settings"]
        self.config_zmq_ipc = config.data[ZMQ_IPC]
        self.config_zmq_tcp = config.data[ZMQ_TCP]

        zmq_url = "ipc://"
        send_mld_ryu_file_path = self.config_zmq_ipc[ZMQ_PUB]
        recv_mld_ryu_file_path = self.config_zmq_ipc[ZMQ_SUB]
        # CHECK TMP FILE(SEND)
        self.mld_ctrl.check_exists_tmp(send_mld_ryu_file_path)
        self.mld_ctrl.check_exists_tmp(recv_mld_ryu_file_path)
        send_mld_ryu_path = zmq_url + send_mld_ryu_file_path
        recv_mld_ryu_path = zmq_url + recv_mld_ryu_file_path

        ctx = zmq.Context()

        # SEND SOCKET CREATE
        self.send_sock_mld_ryu = ctx.socket(zmq.PUB)
        self.send_sock_mld_ryu.bind(send_mld_ryu_path)
        print("send_mld_ryu_path %s", send_mld_ryu_path)
        # RECV SOCKET CREATE
        self.recv_sock_mld_ryu = ctx.socket(zmq.SUB)
        self.recv_sock_mld_ryu.connect(recv_mld_ryu_path)
        self.recv_sock_mld_ryu.setsockopt(zmq.SUBSCRIBE, "")
        print("recv_mld_ryu_path %s", recv_mld_ryu_path)

        # Packetの作成
        eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q,
                                src=HOST_MACADDR1,
                                dst=HOST_MACADDR2)
        vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6, vid=100)
        hop = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                            data=[ipv6.option(type_=5, len_=2, data=""),
                                  ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=SRC_IP, dst=DST_IP,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=hop)
        mld = icmpv6_extend(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                            data=icmpv6.mldv2_query(address=MC_ADDR1))

        packet = eth / vln / ip6 / mld
        packet.serialize()

        #【実行】
        send_hub = hub.spawn(self.mld_ctrl.receive_from_mld)
        # ループに入る分処理待ち
        self.send_sock_mld_ryu.send(cPickle.dumps(packet, protocol=0))
        #self.mld_ctrl.recv_sock.send(cPickle.dumps(packet, protocol=0))
        hub.sleep(3)
        # ループを抜ける
        self.mld_ctrl.loop_flg = False
        send_hub.wait()
        send_hub.kill()
        self.mld_ctrl.loop_flg = True
        """
        # 【実行】
        result = self.mld_ctrl.receive_from_mld()

        # 【結果】
        print("result %s", result)
        assert_equal(result, None)
        """

    def test_receive_from_mld_Failuer001(self):
        # mld_controller.receive_from_mld
        logger.debug("test_receive_from_mld_Failuer001")
        """
        試験方法自体を検討する必要あり、
        まず、無限ループを止められる実装を行う必要があり。
        概要：MLD_Process受信処理
        条件：正常に動作するであろうデータを設定し、実行する
        結果：resultがNoneであること
        """

        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        self.mld_ctrl.loop_flg = True

        config = read_json(COMMON_PATH + mld_const.CONF_FILE)
        self.config = config.data["settings"]
        self.config_zmq_ipc = config.data[ZMQ_IPC]
        self.config_zmq_tcp = config.data[ZMQ_TCP]

        zmq_url = "ipc://"
        send_mld_ryu_file_path = self.config_zmq_ipc[ZMQ_PUB]
        recv_mld_ryu_file_path = self.config_zmq_ipc[ZMQ_SUB]
        # CHECK TMP FILE(SEND)
        self.mld_ctrl.check_exists_tmp(send_mld_ryu_file_path)
        self.mld_ctrl.check_exists_tmp(recv_mld_ryu_file_path)
        send_mld_ryu_path = zmq_url + send_mld_ryu_file_path
        recv_mld_ryu_path = zmq_url + recv_mld_ryu_file_path

        ctx = zmq.Context()

        # SEND SOCKET CREATE
        self.send_sock_mld_ryu = ctx.socket(zmq.PUB)
        self.send_sock_mld_ryu.bind(send_mld_ryu_path)
        print("send_mld_ryu_path %s", send_mld_ryu_path)
        # RECV SOCKET CREATE
        self.recv_sock_mld_ryu = ctx.socket(zmq.SUB)
        self.recv_sock_mld_ryu.connect(recv_mld_ryu_path)
        self.recv_sock_mld_ryu.setsockopt(zmq.SUBSCRIBE, "")
        print("recv_mld_ryu_path %s", recv_mld_ryu_path)

        # Packetの作成
        eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q,
                                src=HOST_MACADDR1,
                                dst=HOST_MACADDR2)
        vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6, vid=100)
        hop = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                            data=[ipv6.option(type_=5, len_=2, data=""),
                                  ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=SRC_IP, dst=DST_IP,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=hop)
        mld = icmpv6_extend(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                            data=icmpv6.mldv2_query(address=MC_ADDR1))

        packet = eth / vln / ip6 / mld
        packet.serialize()

        try:
            #【実行】
            send_hub = hub.spawn(self.mld_ctrl.receive_from_mld)
            # ループに入る分処理待ち
            self.send_sock_mld_ryu.send(cPickle.dumps(None, protocol=0))
            logger.debug("test_receive_from_mld_Failuer001 [self.mld_ctrl.recv_sock.send]")

            hub.sleep(10)

        except Exception as e:
            # 【結果】
            logger.debug("test_receive_from_mld_Failuer001 [Exception] %s", e)
            assert_raises(Exception, e)
        finally:
            # ループを抜ける
            self.mld_ctrl.loop_flg = False
            send_hub.wait()
            send_hub.kill()
            self.mld_ctrl.loop_flg = True

    def test_send_msg_to_flowmod_Success001(self):
        # mld_controller.send_msg_to_flowmod(self, msgbase, flowmod):
        logger.debug("test_send_msg_to_flowmod_Success001")
        """
        概要：FlowMod送信処理
        条件：正常に動作するであろうデータを設定し、実行する
        結果：resultがNoneであること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 33333

        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)

        flowmoddata = flow_mod_data(datapathid=datapath.id,
                                    table_id=0, priority=0, match=0,
                                    instructions=[],
                                    command=ofproto_v1_3.OFPFC_ADD,
                                    out_port=0, out_group=0)

        actions = [ofproto_v1_3_parser.OFPActionOutput(
                                                    ofproto_v1_3.OFPP_NORMAL)]
        instructions = [ofproto_v1_3_parser.OFPInstructionActions(
                                            ofproto_v1_3.OFPIT_APPLY_ACTIONS,
                                            actions)]
        ofp_match = ofproto_v1_3_parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6,
                                            ip_proto=inet.IPPROTO_ICMPV6)

        flowmoddata.instructions = instructions
        flowmoddata.match = ofp_match

        flowmod = self.mld_ctrl.create_flow_mod(datapath, flowmoddata)

        # 【実行】
        result = self.mld_ctrl.send_msg_to_flowmod(ev.msg.datapath, flowmod)

        # 【結果】
        logger.debug("test_send_msg_to_flowmod_Success001 [result] %s",
                     str(result))
        assert_equal(result, None)

    def test_send_msg_to_barrier_request_Success001(self):
        # mld_controller.send_msg_to_barrier_request(self, msgbase):
        logger.debug("test_send_msg_to_barrier_request_Success001")
        """
        概要：BarrierRequest送信処理
        条件：正常に動作するであろうデータを設定し、実行する
        結果：resultがNoneであること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 44444

        # FeaturesRequestEventの作成
        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)

        # 【実行】
        result = self.mld_ctrl.send_msg_to_barrier_request(ev.msg.datapath)

        # 【結果】
        logger.debug("test_send_msg_to_barrier_request_Success001 [result] %s",
                     str(result))
        assert_equal(result, None)

    def test_send_msg_to_packetout_Success001(self):
        # mld_controller.send_msg_to_packetout(self, msgbase, packetout):
        logger.debug("test_send_msg_to_packetout_Success001")
        """
        概要：PacketOut送信処理
        条件：正常に動作するであろうデータを設定し、実行する
        結果：resultがNoneであること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        packetoutdata = ""

        # FeaturesRequestEventの作成
        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)

        # 【実行】
        result = self.mld_ctrl.send_msg_to_packetout(ev.msg.datapath, packetoutdata)

        # 【結果】
        logger.debug("test_send_msg_to_packetout_Success001 [result] %s",
                     str(result))
        assert_equal(result, None)

    def test_check_zmq_type_Success001(self):
        # mld_controller.check_zmq_type(self, zmq_type)
        logger.debug("test_check_zmq_type_Success001")
        """
        概要：zmqで使用するurlの妥当性チェック
        条件：zmq_url=ipc://
        結果：resultがTrueであること
        """
        # 【前処理】
        zmq_type = "ipc"

        # 【実行】
        result = self.mld_ctrl.check_zmq_type(zmq_type)

        # 【結果】
        logger.debug("test_check_zmq_type_Success001 [result] %s", str(result))
        assert_equal(result, True)

    def test_check_zmq_type_Success002(self):
        # mld_controller.check_zmq_type(self, zmq_type)
        logger.debug("test_check_zmq_type_Success002")
        """
        概要：zmqで使用するurlの妥当性チェック
        条件：zmq_url=tcp://
        結果：resultがTrueであること
        """
        # 【前処理】
        zmq_type = "tcp"

        # 【実行】
        result = self.mld_ctrl.check_zmq_type(zmq_type)

        # 【結果】
        logger.debug("test_check_zmq_type_Success002 [result] %s", str(result))
        assert_equal(result, False)

    def test_check_zmq_type_Failer001(self):
        # mld_controller.check_zmq_type(self, zmq_type)
        logger.debug("test_check_zmq_type_Failer001")
        """
        概要：zmqで使用するurlの妥当性チェック
        条件：zmq_url=ipf:///
        結果：Exceptionが発生すること
        """
        # 【前処理】
        zmq_type = "upd"
        try:
            # 【実行】
            result = self.mld_ctrl.check_zmq_type(zmq_type)
            logger.debug("test_check_zmq_type_Failer001 [result] %s", str(result))
        except Exception as e:
            # 【結果】
            logger.debug("test_check_zmq_type_Failer001 [Exception] %s", e)
            assert_raises(Exception, e)
        return

    def test_check_exists_tmp_Success001(self):
        # mld_controller.check_exists_tmp(self, filename)
        logger.debug("test_check_exists_tmp_Success001")
        """
        概要：zmqで使用するipcのtmpファイルを格納するディレクトリの存在チェック
        条件：ディレクトが存在しない
        結果：引数に渡したディレクトリ、ファイル名にて
              ディレクトリ、ファイルが作成されること
        """
        # 【前処理】
        send_file_path = SEND_FILE_PATH + "/ryu-mld-test"

        # 【実行】
        self.mld_ctrl.check_exists_tmp(send_file_path)

        # 【結果】
        logger.debug("test_check_exists_tmp_Success001 [failepath] %s",
                     os.path.exists(send_file_path))
        assert_equal(os.path.exists(send_file_path), True)

    def test_check_exists_tmp_Success002(self):
        # mld_controller.check_exists_tmp(self, filename)
        logger.debug("test_check_exists_tmp_Success002")
        """
        概要：zmqで使用するipcのtmpファイルの存在チェック
        条件：tmpファイルが存在する
        結果：引数に渡したファイル名のtmpファイルが作成されていること
        """
        # 【前処理】
        send_file_path = SEND_FILE_PATH + "/ryu-mld-test"

        # 【実行】
        self.mld_ctrl.check_exists_tmp(send_file_path)

        # 【結果】
        logger.debug("test_check_exists_tmp_Success002 [failepath] %s",
                     os.path.exists(send_file_path))
        assert_equal(os.path.exists(send_file_path), True)

        # 【後処理】後続試験のため、作成したファイルを削除
        os.remove(send_file_path)

    def test_check_exists_tmp_Success003(self):
        # mld_controller.check_exists_tmp(self, filename)
        logger.debug("test_check_exists_tmp_Success003")
        """
        概要：zmqで使用するipcのtmpファイルの存在チェック
        条件：tmpファイルが存在しない
        結果：引数に渡したファイル名のtmpファイルが作成されていること
        """
        # 【前処理】
        send_file_path = SEND_FILE_PATH + "/ryu-mld-test"

        # 【実行】
        self.mld_ctrl.check_exists_tmp(send_file_path)

        # 【結果】
        logger.debug("test_check_exists_tmp_Success003 [failepath] %s",
                     os.path.exists(send_file_path))
        assert_equal(os.path.exists(send_file_path), True)

        # 【後処理】後続試験のため、作成したファイルを削除
        os.remove(send_file_path)
        os.rmdir(SEND_FILE_PATH)

    def test_main_dispacher_handler_Success001(self):
        # mld_controller._main_dispacher_handler
        logger.debug("test_main_dispacher_handler_Success001")
        """
        概要：MainDispacherイベント発生時の処理
        条件：dict_msgに存在しないdatapath.idを設定し、実行する
        結果：resultがNoneであること
              dict_msgのdatapath.idに設定している値とhandlerに渡したev.msgが
              一致していること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 3
        datapath.xid = 999
        # FeaturesRequestEventの作成
        featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
        ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)

        #【実行】
        #result = self.mld_ctrl._switch_features_handler(ev)
        result = self.mld_ctrl._main_dispacher_handler(ev)

        # 【結果】
        logger.debug("test_main_dispacher_handler_Success001 [result] %s",
                     str(result))
        assert_equal(result, None)
        #assert_equal(self.mld_ctrl.dict_msg[datapath.id], ev.msg)

    def test_main_dispacher_handler_Failuer001(self):
        # mld_controller._main_dispacher_handler
        logger.debug("test_main_dispacher_handler_Failuer001")
        """
        概要：MainDispacherイベント発生時の処理
        条件：例外が発生する様ev.msgにNoneを設定し、実行する
        結果：Exceptionが発生すること
        """
        try:
            # 【前処理】
            # DummyDatapathを生成
            datapath = _Datapath()
            # DummyDatapathidを設定
            datapath.id = 888
            datapath.xid = 999
            # FeaturesRequestEventの作成
            featuresRequest = ofproto_v1_3_parser.OFPFeaturesRequest(datapath)
            ev = ofp_event.EventOFPFeaturesRequest(featuresRequest)
            ev.msg = None

            #【実行】
            #self.mld_ctrl._switch_features_handler(ev)
            self.mld_ctrl._main_dispacher_handler(ev)

        except Exception as e:
            # 【結果】
            logger.debug("test_main_dispacher_handler_Failuer001[Exception] %s",
                         e)
            assert_raises(Exception, e)
        return

    def test_barrier_reply_handler_Success001(self):
        # mld_controller._barrier_reply_handler(self, ev)
        logger.debug("test_barrier_reply_handler_Success001")
        """
        概要：BarrierReplyイベント発生時の処理
        条件：正常に動作するであろうdatapathを設定し、実行する
        結果：resultがNoneであること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 55555

        # OFPBarrierReplyEventの作成
        barrierReply = ofproto_v1_3_parser.OFPBarrierReply(datapath)
        ev = ofp_event.EventOFPBarrierReply(barrierReply)

        # 【実行】
        result = self.mld_ctrl._barrier_reply_handler(ev)

        # 【結果】
        logger.debug("test_barrier_reply_handler_Success001 [result] %s",
                     str(result))
        assert_equal(result, None)

    def test_barrier_reply_handler_Failuer001(self):
        # mld_controller._barrier_reply_handler(self, ev)
        logger.debug("test_barrier_reply_handler_Failuer001")
        """
        概要：BarrierReplyイベント発生時の処理
        条件：例外が発生する様ev.msgにNoneを設定し、実行する
        結果：Exceptionが発生すること
        """
        try:
            # 【前処理】
            # DummyDatapathを生成
            datapath = _Datapath()
            # DummyDatapathidを設定
            datapath.id = None
            datapath.xid = 55555

            # OFPBarrierReplyEventの作成
            barrierReply = ofproto_v1_3_parser.OFPBarrierReply(datapath)
            ev = ofp_event.EventOFPBarrierReply(barrierReply)
            ev.msg = None
            # 【実行】
            self.mld_ctrl._barrier_reply_handler(ev)

        except Exception as e:
            # 【結果】
            logger.debug("test_barrier_reply_handler_Failuer001[Exception]%s",
                         e)
            assert_raises(Exception, e)
        return

    def test_packet_in_handler_Success001(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Success001")
        """
        概要：PacketInイベント発生時の処理
        条件：正常に動作するであろうDummyのPacket_Inデータを設定し、実行する
                PacketInTYPE=MLD_LISTENER_QUERY
        結果：mldにパケットが送信されること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q,
                                src=HOST_MACADDR1,
                                dst=HOST_MACADDR2)
        vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6, vid=100)
        hop = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                            data=[ipv6.option(type_=5, len_=2, data=""),
                                  ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=SRC_IP, dst=DST_IP,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=hop)
        mld = icmpv6_extend(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                            data=icmpv6.mldv2_query(address=MC_ADDR1))

        packet = eth / vln / ip6 / mld
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        result = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Success001 [result] %s",
                     str(result))
        assert_equal(result, None)

    def test_packet_in_handler_Success002(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Success002")
        """
        概要：PacketInイベント発生時の処理
        条件：正常に動作するであろうDummyのPacket_Inデータを設定し、実行する
                PacketInTYPE=MLDV2_LISTENER_REPORT
                FILTER_MODE=ALLOW_NEW_SOURCES/CHANGE_TO_INCLUDE_MODE
        結果：mldにパケットが送信されること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        records = []
        record_allow = icmpv6.mldv2_report_group()
        record_allow.type_ = icmpv6.ALLOW_NEW_SOURCES
        records.append(record_allow)

        record_change = icmpv6.mldv2_report_group()
        record_change.type_ = icmpv6.CHANGE_TO_INCLUDE_MODE
        records.append(record_change)

        mldv2_report_ = icmpv6.mldv2_report()
        mldv2_report_.records = records

        eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q,
                                src=HOST_MACADDR1,
                                dst=HOST_MACADDR2)
        vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6, vid=100)
        hop = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                            data=[ipv6.option(type_=5, len_=2, data=""),
                                  ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=SRC_IP, dst=DST_IP,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=hop)
        mld = icmpv6_extend(type_=icmpv6.MLDV2_LISTENER_REPORT,
                            data=mldv2_report_)

        packet = eth / vln / ip6 / mld
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        result = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Success002 [result] %s",
                     str(result))
        assert_equal(result, None)

    def test_packet_in_handler_Success003(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Success003")
        """
        概要：PacketInイベント発生時の処理
        条件：正常に動作するであろうDummyのPacket_Inデータを設定し、実行する
                PacketInTYPE=MLDV2_LISTENER_REPORT
                FILTER_MODE=MODE_IS_INCLUDE
        結果：mldにパケットが送信されること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        records = []
        record_mode = icmpv6.mldv2_report_group()
        record_mode.type_ = icmpv6.MODE_IS_INCLUDE
        records.append(record_mode)

        mldv2_report_ = icmpv6.mldv2_report()
        mldv2_report_.records = records

        eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q,
                                src=HOST_MACADDR1,
                                dst=HOST_MACADDR2)
        vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6, vid=100)
        hop = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                            data=[ipv6.option(type_=5, len_=2, data=""),
                                  ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=SRC_IP, dst=DST_IP,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=hop)
        mld = icmpv6_extend(type_=icmpv6.MLDV2_LISTENER_REPORT,
                            data=mldv2_report_)

        packet = eth / vln / ip6 / mld
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        result = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Success003 [result] %s",
                     str(result))
        assert_equal(result, None)

    def test_packet_in_handler_Success004(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Success004")
        """
        概要：PacketInイベント発生時の処理
        条件：正常に動作するであろうDummyのPacket_Inデータを設定し、実行する
                PacketInTYPE=MLDV2_LISTENER_REPORT
                FILTER_MODE=BLOCK_OLD_SOURCES
        結果：mldにパケットが送信されること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        records = []
        record_block = icmpv6.mldv2_report_group()
        record_block.type_ = icmpv6.BLOCK_OLD_SOURCES
        records.append(record_block)

        mldv2_report_ = icmpv6.mldv2_report()
        mldv2_report_.records = records

        eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q,
                                src=HOST_MACADDR1,
                                dst=HOST_MACADDR2)
        vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6, vid=100)
        hop = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                            data=[ipv6.option(type_=5, len_=2, data=""),
                                  ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=SRC_IP, dst=DST_IP,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=hop)
        mld = icmpv6_extend(type_=icmpv6.MLDV2_LISTENER_REPORT,
                            data=mldv2_report_)

        packet = eth / vln / ip6 / mld
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        result = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Success004 [result] %s",
                     str(result))
        assert_equal(result, None)

    def test_packet_in_handler_Success005(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Success005")
        """
        概要：PacketInイベント発生時の処理
        条件：self.check_vlan_flgに「True/False」を設定し、実行する
        結果：mldにパケットが送信されること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        records = []
        record_block = icmpv6.mldv2_report_group()
        record_block.type_ = icmpv6.BLOCK_OLD_SOURCES
        records.append(record_block)

        mldv2_report_ = icmpv6.mldv2_report()
        mldv2_report_.records = records

        eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q,
                                src=HOST_MACADDR1,
                                dst=HOST_MACADDR2)
        vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6, vid=100)
        hop = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                            data=[ipv6.option(type_=5, len_=2, data=""),
                                  ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=SRC_IP, dst=DST_IP,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=hop)
        mld = icmpv6_extend(type_=icmpv6.MLDV2_LISTENER_REPORT,
                            data=mldv2_report_)

        packet = eth / vln / ip6 / mld
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        self.mld_ctrl.check_vlan_flg = "True"
        result_ture = self.mld_ctrl._packet_in_handler(ev)
        self.mld_ctrl.check_vlan_flg = "False"
        result_false = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Success005 [result_ture] %s",
                     str(result_ture))
        logger.debug("test_packet_in_handler_Success005 [result_false] %s",
                     str(result_false))
        assert_equal(result_ture, None)
        assert_equal(result_false, None)

    def test_packet_in_handler_Failure001(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Failure001")
        """
        概要：PacketInイベント発生時の処理
        条件：パケットにvlanが設定されていない場合
        結果：戻り値がFalseになっていること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        packet = Packet()
#        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
        packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.MLD_LISTENER_QUERY,
                                          data=icmpv6.mldv2_query()))
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        result = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Failure001 [result] %s",
                     str(result))
        assert_equal(result, False)

    def test_packet_in_handler_Failure002(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Failure002")
        """
        概要：PacketInイベント発生時の処理
        条件：パケットにIPV6が設定されていない場合
        結果：戻り値がFalseになっていること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        packet = Packet()
        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
#       packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.MLD_LISTENER_QUERY,
                                          data=icmpv6.mldv2_query()))
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        result = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Failure002 [result] %s",
                     str(result))
        assert_equal(result, False)

    def test_packet_in_handler_Failure003(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Failure003")
        """
        概要：PacketInイベント発生時の処理
        条件：パケットにICMPV6が設定されていない場合
        結果：戻り値がFalseになっていること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        packet = Packet()
        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
        packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
#        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
#        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.MLD_LISTENER_QUERY,
#                                          data=icmpv6.mldv2_query()))
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        result = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Failure003 [result] %s",
                     str(result))
        assert_equal(result, False)

    def test_packet_in_handler_Failure004(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Failure004")
        """
        概要：PacketInイベント発生時の処理
        条件：パケットにICMPV6のTYPEに(MLD_LISTENER_QUERY/MLDV2_LISTENER_REPORT)
              以外が設定されている場合
        結果：戻り値がFalseになっていること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        packet = Packet()
        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
        packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.ICMPV6_ECHO_REQUEST,
                                          data=icmpv6.mldv2_query()))
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        result = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Failure004 [result] %s",
                     str(result))
        assert_equal(result, False)

    def test_packet_in_handler_Failure005(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Failure005")
        """
        概要：PacketInイベント発生時の処理
        条件：パケットにICMPV6のTYPEがMLDV2_LISTENER_REPORTで
              detaにrecordが存在しない場合
        結果：戻り値がFalseになっていること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        packet = Packet()
        packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
        packet.add_protocol(vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6))
        packet.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
        packet.add_protocol(icmpv6.icmpv6(type_=icmpv6.MLDV2_LISTENER_REPORT,
                                          data=icmpv6.mldv2_report()))
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        result = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Failure005 [result] %s", str(result))
        assert_equal(result, False)

    def test_packet_in_handler_Failure006(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Failure006")
        """
        概要：PacketInイベント発生時の処理
        条件：パケットにICMPV6のTYPEがMLDV2_LISTENER_REPORTで
              FILTER_MODEに(MODE_IS_INCLUDE/CHANGE_TO_INCLUDE_MODE/
                            ALLOW_NEW_SOURCES/BLOCK_OLD_SOURCES)
              以外が設定されている場合
        結果：戻り値がFalseになっていること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
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

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        result = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Failure006 [result] %s",
                     str(result))
        assert_equal(result, None)

    def test_packet_in_handler_Failure007(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Failure007")
        """
        概要：PacketInイベント発生時の処理
        条件：self.check_vlan_flgに「True」を設定し、VLANを設定せずに実行する
        結果：エラーとならずにmldにパケットが送信されること
        """
        # 【前処理】
        # DummyDatapathを生成
        datapath = _Datapath()
        # DummyDatapathidを設定
        datapath.id = 1
        datapath.xid = 999
        # Packetの作成
        records = []
        record_allow = icmpv6.mldv2_report_group()
        record_allow.type_ = icmpv6.ALLOW_NEW_SOURCES
        records.append(record_allow)

        record_change = icmpv6.mldv2_report_group()
        record_change.type_ = icmpv6.CHANGE_TO_INCLUDE_MODE
        records.append(record_change)

        mldv2_report_ = icmpv6.mldv2_report()
        mldv2_report_.records = records

#        eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q,
#                                src=HOST_MACADDR1,
#                                dst=HOST_MACADDR2)
        eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_IPV6,
                                src=HOST_MACADDR1,
                                dst=HOST_MACADDR2)

#        vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6, vid=100)
        hop = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                            data=[ipv6.option(type_=5, len_=2, data=""),
                                  ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=SRC_IP, dst=DST_IP,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=hop)
        mld = icmpv6_extend(type_=icmpv6.MLDV2_LISTENER_REPORT,
                            data=mldv2_report_)

#        packet = eth / vln / ip6 / mld
        packet = eth / ip6 / mld
        packet.serialize()

        # PacketInEventの作成
        packetIn = OFPPacketIn(datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                               match=OFPMatch(in_port=1),
                               data=buffer(packet.data))
        ev = ofp_event.EventOFPPacketIn(packetIn)

        # 【実行】
        self.mld_ctrl.check_vlan_flg = "True"
        result_ture = self.mld_ctrl._packet_in_handler(ev)

        # 【結果】
        logger.debug("test_packet_in_handler_Failure007 [result_ture] %s",
                     str(result_ture))
        assert_not_equal(result_ture, None)

    def test_packet_in_handler_Failure008(self):
        # mld_controller._packet_in_handler(self, ev)
        logger.debug("test_packet_in_handler_Failure008")
        """
        概要：PacketInイベント発生時の処理
        条件：例外を発生させるためmatchにNoneを設定し、実行する
        結果：Exceptionが発生すること
        """
        try:
            # 【前処理】
            # DummyDatapathを生成
            datapath = _Datapath()
            # DummyDatapathidを設定
            datapath.id = 1
            datapath.xid = 999
            # Packetの作成
            records = []
            record_allow = icmpv6.mldv2_report_group()
            record_allow.type_ = icmpv6.ALLOW_NEW_SOURCES
            records.append(record_allow)

            record_change = icmpv6.mldv2_report_group()
            record_change.type_ = icmpv6.CHANGE_TO_INCLUDE_MODE
            records.append(record_change)

            mldv2_report_ = icmpv6.mldv2_report()
            mldv2_report_.records = records

            eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q,
                                    src=HOST_MACADDR1,
                                    dst=HOST_MACADDR2)

            vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6, vid=100)
            hop = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                                data=[ipv6.option(type_=5, len_=2, data=""),
                                      ipv6.option(type_=1, len_=0)])]
            ip6 = ipv6.ipv6(src=SRC_IP, dst=DST_IP,
                            nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=hop)
            mld = icmpv6_extend(type_=icmpv6.MLDV2_LISTENER_REPORT,
                                data=mldv2_report_)

            packet = eth / vln / ip6 / mld
            packet.serialize()

            # PacketInEventの作成
            packetIn = OFPPacketIn(datapath,
                                   buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                                   match=None, data=buffer(packet.data))
            ev = ofp_event.EventOFPPacketIn(packetIn)

            # 【実行】
            self.mld_ctrl.check_vlan_flg = "True"
            self.mld_ctrl._packet_in_handler(ev)

        except Exception as e:
            # 【結果】
            logger.debug("test_packet_in_handler_Failure008 [Exception] %s", e)
            assert_raises(Exception, e)
        return

    def test_init_Success001(self):
        # mld_controller.__init__(self, *args, **kwargs)
        try:
            # システムモジュールのソケットに対しパッチを適用
            patcher.monkey_patch()

            # ループフラグの設定
            self.loop_flg = True

            # 設定情報の読み込み
            config = read_json(COMMON_PATH + mld_const.CONF_FILE)
            self.logger.debug("config_info:%s", str(config.data))
            self.config = config.data[SETTING]

            # zmq設定情報の読み込み
            zmq_type = self.config[ZMQ_TYPE]
            self.zmq_pub = None
            self.zmq_sub = None

            # CHECK zmq用URL
            if self.check_zmq_type(self.config[ZMQ_TYPE]):
                # IPCによるSoket設定の読み込み
                self.config_zmq_ipc = config.data[ZMQ_IPC]
                self.zmq_pub = self.config_zmq_ipc[ZMQ_PUB]
                self.zmq_sub = self.config_zmq_ipc[ZMQ_SUB]
                # CHECK TMP FILE(SEND)
                self.check_exists_tmp(self.zmq_pub)
                # CHECK TMP FILE(RECV)
                self.check_exists_tmp(self.zmq_sub)
            else:
                # TCPによるSoket設定の読み込み
                self.config_zmq_tcp = config.data[ZMQ_TCP]
                self.zmq_sub = self.config_zmq_tcp[MLD_SERVER_IP]
                self.zmq_sub_list = self.zmq_sub.split(PORT_DELIMIT)
                # zmq_subのポート設定を取得し、zmq_pubのIPアドレスに付与
                self.zmq_pub = SEND_IP + PORT_DELIMIT + self.zmq_sub_list[1]

            # zmq_urlの設定
            zmq_url = zmq_type.lower() + URL_DELIMIT
            # ZeroMQ送受信用ソケット生成
            self.create_socket(zmq_url + self.zmq_pub, zmq_url + self.zmq_sub)

            # VLANチェックフラグの読み込み
#            self.check_vlan_flg = self.config[CHECK_VLAN_FLG]

        except Exception as e:
            # 【結果】
            logger.debug("test_init_Success001")
            logger.debug("test_packet_in_handler_Failure008 [Exception] %s", e)
            assert_raises(Exception, e)
        return

if __name__ == '__main__':
    unittest.main()
