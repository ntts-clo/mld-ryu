# coding: utf-8
# nose install
#  >sudo pip install nose
# coverage install
#  >sudo pip install coverage
# mox install
#  >sudo pip install mox
#

import os
import sys
import logging
import unittest
import time
import ctypes
import cPickle
from mox import Mox, ExpectedMethodCallsError, IsA
from nose.tools import ok_, eq_
from nose.tools.nontrivial import raises
from nose.plugins.attrib import attr
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.ofproto import ofproto_v1_3, inet
from multiprocessing import Value
hub.patch()

APP_PATH = "../app/"
sys.path.append(APP_PATH)
from mld_process import mld_process

COMMON_PATH = "../../common/"
sys.path.append(COMMON_PATH)
from zmq_dispatch import dispatch, packet_out_data
from read_json import read_json
import mld_const as const

logger = logging.getLogger(__name__)


class test_mld_process():

    # このクラスのテストケースを実行する前に１度だけ実行する
    @classmethod
    def setup_class(cls):
        logger.debug("setup")

        config = read_json(COMMON_PATH + const.CONF_FILE)
        cls.config = config.data["settings"]

        cls.addressinfo = []
        for line in open(COMMON_PATH + const.ADDRESS_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                columns = list(line[:-1].split(","))
                for column in columns:
                    cls.addressinfo.append(column)

        mc_info = read_json(COMMON_PATH + const.MULTICAST_INFO)
        cls.mc_info_list = mc_info.data["mc_info"]

        cls.mld_proc = mld_process()

    # このクラスのテストケースをすべて実行した後に１度だけ実行する
    @classmethod
    def teardown_class(cls):
        logger.debug("teardown")

    def setup(self):
        self.mocker = Mox()
        # 設定値の初期化
        self.mld_proc.ch_info.channel_info = {}
        self.mld_proc.ch_info.user_info_list = []
        self.mld_proc.config = self.config

    def teardown(self):
        self.mocker.UnsetStubs()

    @attr(do=False)
    def test_init(self):
        logger.debug("test_init")

        # ロガーの設定
        ok_(self.mld_proc.logger)

        # 視聴情報初期化
        ok_(self.mld_proc.ch_info)

        # 設定情報読み込み
        eq_(self.mld_proc.config, self.config)

        # アドレス情報
        eq_(self.mld_proc.addressinfo, self.addressinfo)

        # スイッチ情報読み込み
        switches = read_json(COMMON_PATH + const.SWITCH_INFO)
        eq_(self.mld_proc.switch_mld_info,
            switches.data["switch_mld_info"])
        eq_(self.mld_proc.switch_mc_info,
            switches.data["switch_mc_info"])

        # マルチキャスト情報読み込み
        eq_(self.mld_proc.mc_info_list, self.mc_info_list)

        # bvidパターン読み込み
        bvid_variation = read_json(COMMON_PATH + const.BVID_VARIATION)
        eq_(self.mld_proc.bvid_variation,
            bvid_variation.data["bvid_variation"])

        # ZeroMQ送受信用設定
        ok_(self.mld_proc.send_sock)
        ok_(self.mld_proc.recv_sock)

        # Flowmod生成用インスタンス
        ok_(self.mld_proc.flowmod_gen)

    @attr(do=False)
    def test_check_exists_tmp_exsist(self):
        # 存在するファイルパスを指定
        filepath = "/tmp"
        self.mld_proc.check_exists_tmp(filepath)

    @attr(do=False)
    def test_check_exists_tmp_nofile(self):
        # ファイルパスは存在するがファイルが存在しない
        filedir = "/tmp/tempdir"
        filepath = filedir + "/tempfile"
        os.makedirs(filedir)

        self.mld_proc.check_exists_tmp(filepath)
        os.remove(filepath)
        os.rmdir(filedir)

    @attr(do=False)
    def test_check_exists_tmp_nodir(self):
        # 存在しないファイルパスを指定
        filedir = "/tmp/tempdir"
        filepath = filedir + "/tempfile"

        self.mld_proc.check_exists_tmp(filepath)
        os.remove(filepath)
        os.rmdir(filedir)

    @attr(do=False)
    def test_cretate_scoket001(self):
        zmq_url = "ipc://"
        send_file_path = "/tmp/feeds/ut/mld-mld"
        recv_file_path = "/tmp/feeds/ut/ryu-mld"
        send_path = zmq_url + send_file_path
        recv_path = zmq_url + recv_file_path

        # CHECK TMP FILE(SEND)
        self.mld_proc.check_exists_tmp(send_file_path)
        # CHECK TMP FILE(RECV)
        self.mld_proc.check_exists_tmp(recv_file_path)

        self.mld_proc.cretate_scoket(send_path, recv_path)

        ok_(self.mld_proc.send_sock)
        ok_(self.mld_proc.recv_sock)

        os.remove(send_file_path)
        os.remove(recv_file_path)
        os.rmdir("/tmp/feeds/ut/")

    @attr(do=False)
    def test_cretate_scoket002(self):
        zmq_url = "tcp://"
        send_path = zmq_url + "127.0.0.1:7002"
        recv_path = zmq_url + "0.0.0.0:7002"

        self.mld_proc.cretate_scoket(send_path, recv_path)

        ok_(self.mld_proc.send_sock)
        ok_(self.mld_proc.recv_sock)

    @attr(do=False)
    def test_send_mldquey_regularly_gq(self):

        self.mld_proc.config["reguraly_query_type"] = "GQ"
        self.mld_proc.config["reguraly_query_interval"] = 5
        self.mld_proc.config["mld_esw_ifname"] = "eth0"

        # send_mldquery([mc_info])呼び出し確認
        mc_info = {"mc_addr": "::", "serv_ip": None}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        send_hub = hub.spawn(self.mld_proc.send_mldquery_regularly)
        # ループに入る分処理待ち
        hub.sleep(3)
        # ループを抜ける
        self.mld_proc.SEND_LOOP = False
        hub.sleep(1)
        send_hub.wait()
        send_hub.kill()
        self.mld_proc.SEND_LOOP = True

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_send_mldquey_regularly_sq(self):
        self.mld_proc.config["reguraly_query_type"] = "SQ"
        self.mld_proc.config["reguraly_query_interval"] = 3
        self.mld_proc.config["mc_query_interval"] = 1
        self.mld_proc.config["mld_esw_ifname"] = "eth0"

        send_hub = hub.spawn(self.mld_proc.send_mldquery_regularly)
        # ループに入る分処理待ち
        hub.sleep(4)
        # ループを抜けさせる
        self.mld_proc.SEND_LOOP = False
        send_hub.wait()
        send_hub.kill()
        self.mld_proc.SEND_LOOP = True

    @attr(do=False)
    def test_wait_query_interval(self):
        # Falseで指定した引数がTrueに更新されていること
        next_interval = Value(ctypes.c_bool, False)
        self.mld_proc.config["reguraly_query_interval"] = 1
        self.mld_proc.wait_query_interval(next_interval)
        self.mld_proc.config["reguraly_query_interval"] = \
            self.config["reguraly_query_interval"]
        ok_(next_interval.value)

    @attr(do=False)
    def test_send_mldquery_no_next_interval(self):
        mc_info_list = [{"mc_addr": "ff38::1:1", "serv_ip": "2001::1:20"},
                        {"mc_addr": "ff38::1:2", "serv_ip": "2001::1:20"}]
        wait_time = 1
        qqrv = 2

        # 呼び出しメソッドのスタブ化
        self.mocker.StubOutWithMock(self.mld_proc, "create_mldquery")
        self.mocker.StubOutWithMock(self.mld_proc, "create_packet")
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_sw")
        for mc_info in mc_info_list:
            self.mld_proc.create_mldquery(
                mc_info["mc_addr"], mc_info["serv_ip"]).AndReturn("mld")
            self.mld_proc.create_packet(
                self.addressinfo, self.config["c_tag_id"], "mld").AndReturn(
                "sendpkt")
            for i in range(qqrv):
                self.mld_proc.send_packet_to_sw("sendpkt").AndReturn(0)
        self.mocker.ReplayAll()

        self.mld_proc.send_mldquery(mc_info_list, wait_time)

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_send_mldquery_exists_next_interval(self):
        mc_info_list = [{"mc_addr": "ff38::1:1", "serv_ip": "2001::1:20"},
                        {"mc_addr": "ff38::1:2", "serv_ip": "2001::1:20"}]
        wait_time = 1
        next_interval = Value(ctypes.c_bool, True)

        # next_intervalのvalueがTrueなので送信処理は行わない
        eq_(self.mld_proc.send_mldquery(
            mc_info_list, wait_time, next_interval), -1)

    @attr(do=False)
    def test_create_mldquery_general(self):
        # GeneralQueryを生成する
        mc_addr = "::"
        serv_ip = None

        actual = self.mld_proc.create_mldquery(mc_addr, serv_ip)
        eq_(mc_addr, actual.address)
        eq_([], actual.srcs)
        eq_(self.mld_proc.QUERY_MAX_RESPONSE, actual.maxresp)
        eq_(self.mld_proc.QUERY_QRV, actual.qrv)
        eq_(self.mld_proc.config["reguraly_query_interval"], actual.qqic)

    @attr(do=False)
    def test_create_mldquery_specific(self):
        # SpecificQueryを生成する
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"

        actual = self.mld_proc.create_mldquery(mc_addr, serv_ip)
        eq_(mc_addr, actual.address)
        eq_([serv_ip], actual.srcs)
        eq_(self.mld_proc.QUERY_MAX_RESPONSE, actual.maxresp)
        eq_(self.mld_proc.QUERY_QRV, actual.qrv)
        eq_(self.mld_proc.config["reguraly_query_interval"], actual.qqic)

    @attr(do=False)
    def test_create_mldreport(self):
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        types = [icmpv6.MODE_IS_INCLUDE, icmpv6.MODE_IS_EXCLUDE,
                 icmpv6.CHANGE_TO_INCLUDE_MODE, icmpv6.CHANGE_TO_EXCLUDE_MODE,
                 icmpv6.ALLOW_NEW_SOURCES, icmpv6.BLOCK_OLD_SOURCES]

        # 全typeを持つreportが生成されること
        actual = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)
        eq_(len(types), len(actual.records))

        idx = 0
        for report in actual.records:
            eq_(types[idx], report.type_)
            eq_(mc_addr, report.address)
            eq_([serv_ip], report.srcs)
            idx += 1

    @attr(do=False)
    def test_create_packet_query(self):
        # MLD Queryを持つpacketを生成
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        vid = self.config["c_tag_id"]
        query = self.mld_proc.create_mldquery(mc_addr, serv_ip)
        actual = self.mld_proc.create_packet(
            self.addressinfo, vid, query)

        eth = actual.get_protocol(ethernet.ethernet)
        eq_(self.addressinfo[0], eth.src)
        eq_(self.addressinfo[1], eth.dst)

        vln = actual.get_protocol(vlan.vlan)
        eq_(vid, vln.vid)

        ip6 = actual.get_protocol(ipv6.ipv6)
        eq_(self.addressinfo[2], ip6.src)
        eq_(self.addressinfo[3], ip6.dst)
        # 拡張ヘッダを持っていることを確認
        eq_(inet.IPPROTO_HOPOPTS, ip6.nxt)
        ok_(ip6.ext_hdrs)

        icmp6 = actual.get_protocol(icmpv6.icmpv6)
        eq_(icmpv6.MLD_LISTENER_QUERY, icmp6.type_)
        eq_(query, icmp6.data)

    @attr(do=False)
    def test_create_packet_report(self):
        # MLD Reportを持つpacketを生成
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        vid = self.config["c_tag_id"]
        types = [icmpv6.ALLOW_NEW_SOURCES, icmpv6.CHANGE_TO_INCLUDE_MODE]
        report = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)
        actual = self.mld_proc.create_packet(
            self.addressinfo, vid, report)

        # eth - ipv6まではquery時に確認しているため省略
        icmp6 = actual.get_protocol(icmpv6.icmpv6)
        eq_(icmpv6.MLDV2_LISTENER_REPORT, icmp6.type_)
        eq_(report, icmp6.data)

    @attr(do=False)
    def test_send_packet_to_sw(self):
        # switchに送信できているかは結合時に確認
        eth = ethernet.ethernet()
        vln = vlan.vlan()
        ip6 = ipv6.ipv6()
        icmp6 = icmpv6.icmpv6()
        packet = eth / vln / ip6 / icmp6
        packet.serialize()

        self.mld_proc.config["mld_esw_ifname"] = "eth0"
        self.mld_proc.send_packet_to_sw(packet)

    @attr(do=False)
    def test_send_packet_to_ryu(self):
        # ryu-controllerに送信できているかは結合時に確認
        eth = ethernet.ethernet()
        vln = vlan.vlan()
        ip6 = ipv6.ipv6()
        icmp6 = icmpv6.icmpv6()
        packet = eth / vln / ip6 / icmp6
        packet.serialize()

        self.mld_proc.send_packet_to_ryu(packet)

    @attr(do=False)
    def test_analyse_receive_packet_switch_feature(self):
        # switchとの初回接続時：set_switch_configを呼び出す
        dispatch_ = dispatch(const.CON_SWITCH_FEATURE, 1)

        self.mocker.StubOutWithMock(self.mld_proc, "set_switch_config")
        self.mld_proc.set_switch_config(dispatch_.dispatch)
        self.mocker.ReplayAll()

        self.mld_proc.analyse_receive_packet(dispatch_)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_analyse_receive_packet_packetin_query(self):
        # packet-in受信時：queryであればreply_proxyを呼び出す
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        query = self.mld_proc.create_mldquery(mc_addr, serv_ip)
        data = icmpv6.icmpv6(
            type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY, data=query)
        dispatch_ = dispatch(const.CON_PACKET_IN, 1, data=data)

        # reply_proxy、check_user_timeoutの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "reply_proxy")
        self.mld_proc.reply_proxy()
        self.mocker.StubOutWithMock(self.mld_proc, "check_user_timeout")
        self.mld_proc.check_user_timeout()
        self.mocker.ReplayAll()

        self.mld_proc.analyse_receive_packet(dispatch_)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_analyse_receive_packet_packetin_report(self):
        # packet-in受信時：reportであればmanage_userを呼び出す
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        types = [icmpv6.MODE_IS_INCLUDE]
        report = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)
        data = icmpv6.icmpv6(
            type_=icmpv6.MLDV2_LISTENER_REPORT, data=report)
        dispatch_ = dispatch(const.CON_PACKET_IN, 1, data=data)

        # reply_proxy、check_user_timeoutの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "manage_user")
        self.mld_proc.manage_user(dispatch_.dispatch)
        self.mocker.StubOutWithMock(self.mld_proc, "check_user_timeout")
        self.mld_proc.check_user_timeout()
        self.mocker.ReplayAll()

        self.mld_proc.analyse_receive_packet(dispatch_)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_analyse_receive_packet_other(self):
        # それ以外の場合：なにもしない
        dispatch_ = dispatch("", 1)
        self.mld_proc.analyse_receive_packet(dispatch_)

    @attr(do=False)
    def test_set_switch_config(self):

        datapathid = self.mld_proc.switches[1]["datapathid"]
        dispatch_ = dispatch(const.CON_SWITCH_FEATURE, datapathid)

        # flowmod_gen.initialize_flowsのスタブ化
        self.mocker.StubOutWithMock(
            self.mld_proc.flowmod_gen, "initialize_flows")
        self.mld_proc.flowmod_gen.initialize_flows(
            datapathid=datapathid,
            pbb_isid=self.mld_proc.switch_mld_info["pbb_isid"],
            bvid=self.mld_proc.switch_mld_info["bvid"],
            ivid=self.mld_proc.switch_mld_info["ivid"]).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        self.mocker.ReplayAll()

        self.mld_proc.set_switch_config(dispatch_)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_create_packetout(self):
        datapathid = self.mld_proc.edge_switch["datapathid"]
        packet = ipv6.ipv6()

        actual = self.mld_proc.create_packetout(datapathid, packet)

        ok_(type(actual) is packet_out_data)
        eq_(datapathid, actual.datapathid)
        eq_(ofproto_v1_3.OFPP_CONTROLLER, actual.in_port)
        eq_(ofproto_v1_3.OFP_NO_BUFFER, actual.buffer_id)
        eq_(1, len(actual.actions))
        eq_(self.mld_proc.edge_switch["edge_router_port"],
            actual.actions[0].port)
        eq_(packet, actual.data)

    @attr(do=False)
    @raises(ExpectedMethodCallsError)
    def test_check_user_timeout_no_user(self):
        # 視聴ユーザーがいない場合は何もしない

        # time.time()が呼び出されないことを確認
        mock_time = self.mocker.CreateMock(time)
        mock_time.time()
        self.mocker.ReplayAll()

        self.mld_proc.check_user_timeout()
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_check_user_timeout_no_timeout(self):
        # タイムアウトのユーザーなし
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        datapathid = self.mld_proc.switches[1]["datapathid"]
        port_no = 1
        cid = 2101
        self.mld_proc.config["user_time_out"] = 300

        self.mld_proc.ch_info.update_ch_info(
            mc_addr, serv_ip, datapathid, port_no, cid)
        before_size = len(self.mld_proc.ch_info.user_info_list)

        self.mld_proc.check_user_timeout()
        after_size = len(self.mld_proc.ch_info.user_info_list)

        eq_(before_size, after_size)

        # 元の値に戻す
        self.mld_proc.config["user_time_out"] = self.config["user_time_out"]

    @attr(do=False)
    def test_check_user_timeout_timeout(self):
        # タイムアウトのユーザーあり

        # 2秒でタイムアウトとする
        self.mld_proc.config["user_time_out"] = 2

        mc_addr1 = "ff38::1:1"
        serv_ip = "2001::1:20"
        datapathid2 = self.mld_proc.switches[1]["datapathid"]
        port_no1 = 1
        cid1 = 12101
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no1, cid1)
        cid2 = 12102
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no1, cid2)

        # タイムアウトを起こすために処理待ち
        time.sleep(2)

        port_no2 = 2
        cid3 = 12201
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no2, cid3)
        datapathid3 = self.mld_proc.switches[2]["datapathid"]

        port_no3 = 3
        cid4 = 13301
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid3, port_no3, cid4)

        mc_addr2 = "ff38::1:2"
        cid5 = 22102
        self.mld_proc.ch_info.update_ch_info(
            mc_addr2, serv_ip, datapathid2, port_no1, cid5)

        # check_user_timeout実行前の件数確認
        eq_(5, len(self.mld_proc.ch_info.user_info_list))

        self.mld_proc.check_user_timeout()

        # sleep前の2件がタイムアウト
        eq_(3, len(self.mld_proc.ch_info.user_info_list))

        user_info = self.mld_proc.ch_info.user_info_list[0]
        eq_(mc_addr1, user_info.mc_addr)
        eq_(serv_ip, user_info.serv_ip)
        eq_(datapathid2, user_info.datapathid)
        eq_(port_no2, user_info.port_no)
        eq_(cid3, user_info.cid)

        user_info = self.mld_proc.ch_info.user_info_list[1]
        eq_(mc_addr1, user_info.mc_addr)
        eq_(serv_ip, user_info.serv_ip)
        eq_(datapathid3, user_info.datapathid)
        eq_(port_no3, user_info.port_no)
        eq_(cid4, user_info.cid)

        user_info = self.mld_proc.ch_info.user_info_list[2]
        eq_(mc_addr2, user_info.mc_addr)
        eq_(serv_ip, user_info.serv_ip)
        eq_(datapathid2, user_info.datapathid)
        eq_(port_no1, user_info.port_no)
        eq_(cid5, user_info.cid)

    @attr(do=False)
    def test_reply_proxy_no_user(self):
        # 視聴情報がない場合は何もしない
        actual = self.mld_proc.reply_proxy()
        eq_(-1, actual)

    @attr(do=False)
    def test_reply_proxy_exists_user(self):
        # 視聴情報がある場合、視聴中のmcアドレス分p-out
        mc_addr1 = "ff38::1:1"
        serv_ip = "2001::1:20"
        datapathid2 = 2
        port_no1 = 1
        cid1 = 12101
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no1, cid1)
        cid2 = 12102
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no1, cid2)

        mc_addr2 = "ff38::1:2"
        serv_ip = "2001::1:20"
        cid3 = 22101
        self.mld_proc.ch_info.update_ch_info(
            mc_addr2, serv_ip, datapathid2, port_no1, cid3)

        # send_packet_to_ryuがmcアドレス分(2回)呼び出されることを確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))
        self.mocker.ReplayAll()

        self.mld_proc.reply_proxy()
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_manage_user_reply_nothing(self):
        # update_user_infoがCON_REPLY_NOTHINGを返却する場合なにもしない
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        types = [icmpv6.MODE_IS_INCLUDE]
        mld = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)
        data = icmpv6.icmpv6(
            type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100
        dispatch_ = dispatch(
            const.CON_PACKET_IN, datapathid, in_port, cid, data)

        report = mld.records[0]

        self.mocker.StubOutWithMock(self.mld_proc, "update_user_info")
        self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid, report).AndReturn(
            const.CON_REPLY_NOTHING)
        self.mocker.ReplayAll()

        actual = self.mld_proc.manage_user(dispatch_)
        eq_(-1, actual)

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_manage_user_reply(self):
        # update_user_infoがCON_REPLY_NOTHING以外を返却する場合はreply_to_ryuを呼び出す
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        types = [icmpv6.MODE_IS_INCLUDE]
        mld = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)
        data = icmpv6.icmpv6(
            type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100
        dispatch_ = dispatch(
            const.CON_PACKET_IN, datapathid, in_port, cid, data)

        report = mld.records[0]

        # update_user_infoがCON_REPLY_ADD_MC_GROUPを返却
        self.mocker.StubOutWithMock(self.mld_proc, "update_user_info")
        self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid, report).AndReturn(
            const.CON_REPLY_ADD_MC_GROUP)

        # reply_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "reply_to_ryu")
        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port,
            const.CON_REPLY_ADD_MC_GROUP)
        self.mocker.ReplayAll()

        self.mld_proc.manage_user(dispatch_)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_update_user_info_allow(self):
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100

        types = [icmpv6.ALLOW_NEW_SOURCES]
        mld = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)
        report = mld.records[0]

        # update_ch_infoの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.ch_info, "update_ch_info")
        self.mld_proc.ch_info.update_ch_info(
            mc_addr=mc_addr, serv_ip=serv_ip, datapathid=datapathid,
            port_no=in_port, cid=cid).AndReturn(const.CON_REPLY_NOTHING)
        self.mocker.ReplayAll()

        actual = self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid, report)
        eq_(const.CON_REPLY_NOTHING, actual)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_update_user_info_block(self):
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100

        types = [icmpv6.BLOCK_OLD_SOURCES]
        mld = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)
        report = mld.records[0]

        # remove_ch_infoの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.ch_info, "remove_ch_info")
        self.mld_proc.ch_info.remove_ch_info(
            mc_addr=mc_addr, serv_ip=serv_ip, datapathid=datapathid,
            port_no=in_port, cid=cid).AndReturn(const.CON_REPLY_NOTHING)

        # send_mldqueryの呼び出し確認
        mc_info = {"mc_addr": mc_addr, "serv_ip": serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        actual = self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid, report)
        eq_(const.CON_REPLY_NOTHING, actual)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_update_user_info_include(self):
        # 既存ユーザのMODE_IS_INCLUDEの場合
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100

        types = [icmpv6.MODE_IS_INCLUDE]
        mld = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)
        report = mld.records[0]

        # update_ch_infoの呼び出し確認がCON_REPLY_NOTHINGを返す
        self.mocker.StubOutWithMock(
            self.mld_proc.ch_info, "update_ch_info")
        self.mld_proc.ch_info.update_ch_info(
            mc_addr=mc_addr, serv_ip=serv_ip, datapathid=datapathid,
            port_no=in_port, cid=cid).AndReturn(const.CON_REPLY_NOTHING)
        self.mocker.ReplayAll()

        actual = self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid, report)
        eq_(const.CON_REPLY_NOTHING, actual)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_update_user_info_other(self):
        # 上記以外のtypeはCON_REPLY_NOTHINGを返却
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100

        types = [icmpv6.CHANGE_TO_EXCLUDE_MODE,
                 icmpv6.CHANGE_TO_INCLUDE_MODE,
                 icmpv6.MODE_IS_EXCLUDE]
        mld = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)

        for report in mld.records:
            actual = self.mld_proc.update_user_info(
                mc_addr, serv_ip, datapathid, in_port, cid, report)
            eq_(const.CON_REPLY_NOTHING, actual)

    @attr(do=False)
    def test_reply_to_ryu_add_mc_be(self):
        # reply_typeがCON_REPLY_ADD_MC_GROUPの場合
        mc_addr = str(self.mc_info_list[0]["mc_addr"])
        serv_ip = str(self.mc_info_list[0]["serv_ip"])
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100
        reply_type = const.CON_REPLY_ADD_MC_GROUP

        # ベストエフォートサービス
        self.mld_proc.mc_info_list[0]["type"] = self.mld_proc.BEST_EFFORT
        self.mld_proc.ch_info.update_ch_info(
            mc_addr, serv_ip, datapathid, in_port, cid)

        # flowmod_gen.start_mgをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "start_mg")
        self.mld_proc.flowmod_gen.start_mg(
            multicast_address=mc_addr, datapathid=datapathid,
            portno=in_port, mc_ivid=self.mld_proc.switch_mc_info["ivid"],
            ivid=self.mc_info_list[0]["ivid"],
            pbb_isid=self.mc_info_list[0]["pbb_isid"],
            bvid=4001).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        # create_mldreportの呼び出し確認
        report_types = [icmpv6.ALLOW_NEW_SOURCES,
                        icmpv6.CHANGE_TO_INCLUDE_MODE]
        mld_report = self.mld_proc.create_mldreport(
            mc_address=mc_addr, mc_serv_ip=serv_ip, report_types=report_types)
        self.mocker.StubOutWithMock(self.mld_proc, "create_mldreport")
        self.mld_proc.create_mldreport(
            mc_address=mc_addr, mc_serv_ip=serv_ip,
            report_types=report_types).AndReturn(mld_report)

        self.mocker.ReplayAll()

        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port, reply_type)
        self.mocker.VerifyAll()

        self.mld_proc.mc_info_list[0]["type"] = self.mc_info_list[0]["type"]

    @attr(do=False)
    @raises(ExpectedMethodCallsError)
    def test_reply_to_ryu_add_mc_qa(self):
        # reply_typeがCON_REPLY_ADD_MC_GROUPの場合
        mc_addr = str(self.mc_info_list[0]["mc_addr"])
        serv_ip = str(self.mc_info_list[0]["serv_ip"])
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100
        reply_type = const.CON_REPLY_ADD_MC_GROUP

        # 品質保証サービス
        self.mld_proc.mc_info_list[0]["type"] = self.mld_proc.QUALITY_ASSURANCE
        self.mld_proc.ch_info.update_ch_info(
            mc_addr, serv_ip, datapathid, in_port, cid)

        # flowmod_gen.start_mgをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "start_mg")
        self.mld_proc.flowmod_gen.start_mg(
            multicast_address=mc_addr, datapathid=datapathid,
            portno=in_port, mc_ivid=self.mld_proc.switch_mc_info["ivid"],
            ivid=self.mc_info_list[0]["ivid"],
            pbb_isid=self.mc_info_list[0]["pbb_isid"],
            bvid=4001).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        # create_mldreportが呼び出されないことの確認
        self.mocker.StubOutWithMock(self.mld_proc, "create_mldreport")
        self.mld_proc.create_mldreport(IsA(str), IsA(str), IsA(list))

        self.mocker.ReplayAll()

        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port, reply_type)
        self.mocker.VerifyAll()

        self.mld_proc.mc_info_list[0]["type"] = self.mc_info_list[0]["type"]

    @attr(do=False)
    def test_reply_to_ryu_add_sw(self):
        # reply_typeがCON_REPLY_ADD_SWITCHの場合
        mc_addr = str(self.mc_info_list[0]["mc_addr"])
        serv_ip = str(self.mc_info_list[0]["serv_ip"])
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        reply_type = const.CON_REPLY_ADD_SWITCH

        # flowmod_gen.add_datapathをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "add_datapath")
        self.mld_proc.flowmod_gen.add_datapath(
            multicast_address=mc_addr, datapathid=datapathid,
            portno=in_port, ivid=self.mc_info_list[0]["ivid"],
            pbb_isid=self.mc_info_list[0]["pbb_isid"],
            bvid=-1).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        self.mocker.ReplayAll()

        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port, reply_type)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_reply_to_ryu_add_port(self):
        # reply_typeがCON_REPLY_ADD_PORTの場合
        mc_addr = str(self.mc_info_list[0]["mc_addr"])
        serv_ip = str(self.mc_info_list[0]["serv_ip"])
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        reply_type = const.CON_REPLY_ADD_PORT

        # flowmod_gen.add_portをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "add_port")
        self.mld_proc.flowmod_gen.add_port(
            multicast_address=mc_addr, datapathid=datapathid,
            portno=in_port, ivid=self.mc_info_list[0]["ivid"],
            pbb_isid=self.mc_info_list[0]["pbb_isid"],
            bvid=-1).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        self.mocker.ReplayAll()

        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port, reply_type)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_reply_to_ryu_del_mc_be(self):
        mc_addr = str(self.mc_info_list[0]["mc_addr"])
        serv_ip = str(self.mc_info_list[0]["serv_ip"])
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100
        reply_type = const.CON_REPLY_DEL_MC_GROUP

        # ベストエフォートサービス
        self.mld_proc.mc_info_list[0]["type"] = self.mld_proc.BEST_EFFORT
        self.mld_proc.ch_info.update_ch_info(
            mc_addr, serv_ip, datapathid, in_port, cid)

        # create_mldreportの呼び出し確認
        report_types = [icmpv6.BLOCK_OLD_SOURCES]
        mld_report = self.mld_proc.create_mldreport(
            mc_address=mc_addr, mc_serv_ip=serv_ip, report_types=report_types)
        self.mocker.StubOutWithMock(self.mld_proc, "create_mldreport")
        self.mld_proc.create_mldreport(
            mc_address=mc_addr, mc_serv_ip=serv_ip,
            report_types=report_types).AndReturn(mld_report)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        # flowmod_gen.remove_mgをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "remove_mg")
        self.mld_proc.flowmod_gen.remove_mg(
            multicast_address=mc_addr, datapathid=datapathid,
            portno=in_port, mc_ivid=self.mld_proc.switch_mc_info["ivid"],
            ivid=self.mc_info_list[0]["ivid"],
            pbb_isid=self.mc_info_list[0]["pbb_isid"],
            bvid=4001).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        self.mocker.ReplayAll()

        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port, reply_type)
        self.mocker.VerifyAll()

        self.mld_proc.mc_info_list[0]["type"] = self.mc_info_list[0]["type"]

    @attr(do=False)
    @raises(ExpectedMethodCallsError)
    def test_reply_to_ryu_del_mc_qa(self):
        mc_addr = str(self.mc_info_list[0]["mc_addr"])
        serv_ip = str(self.mc_info_list[0]["serv_ip"])
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100
        reply_type = const.CON_REPLY_DEL_MC_GROUP

        # 品質保証サービス
        self.mld_proc.mc_info_list[0]["type"] = self.mld_proc.QUALITY_ASSURANCE
        self.mld_proc.ch_info.update_ch_info(
            mc_addr, serv_ip, datapathid, in_port, cid)

        # create_mldreportが呼び出されないことの確認
        self.mocker.StubOutWithMock(self.mld_proc, "create_mldreport")
        self.mld_proc.create_mldreport(IsA(str), IsA(str), IsA(list))

        # flowmod_gen.remove_mgをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "remove_mg")
        self.mld_proc.flowmod_gen.remove_mg(
            multicast_address=mc_addr, datapathid=datapathid,
            portno=in_port, mc_ivid=self.mld_proc.switch_mc_info["ivid"],
            ivid=self.mc_info_list[0]["ivid"],
            pbb_isid=self.mc_info_list[0]["pbb_isid"],
            bvid=4001).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        self.mocker.ReplayAll()

        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port, reply_type)
        self.mocker.VerifyAll()

        self.mld_proc.mc_info_list[0]["type"] = self.mc_info_list[0]["type"]

    @attr(do=False)
    def test_reply_to_ryu_del_sw(self):
        # reply_typeがCON_REPLY_DEL_SWITCHの場合
        mc_addr = str(self.mc_info_list[0]["mc_addr"])
        serv_ip = str(self.mc_info_list[0]["serv_ip"])
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        reply_type = const.CON_REPLY_DEL_SWITCH

        # flowmod_gen.remove_datapathをスタブ化
        self.mocker.StubOutWithMock(
            self.mld_proc.flowmod_gen, "remove_datapath")
        self.mld_proc.flowmod_gen.remove_datapath(
            multicast_address=mc_addr, datapathid=datapathid,
            portno=in_port, ivid=self.mc_info_list[0]["ivid"],
            pbb_isid=self.mc_info_list[0]["pbb_isid"],
            bvid=-1).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        self.mocker.ReplayAll()

        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port, reply_type)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_reply_to_ryu_del_port(self):
        # reply_typeがCON_REPLY_DEL_PORTの場合
        mc_addr = str(self.mc_info_list[0]["mc_addr"])
        serv_ip = str(self.mc_info_list[0]["serv_ip"])
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        reply_type = const.CON_REPLY_DEL_PORT

        # flowmod_gen.remove_portをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "remove_port")
        self.mld_proc.flowmod_gen.remove_port(
            multicast_address=mc_addr, datapathid=datapathid,
            portno=in_port, ivid=self.mc_info_list[0]["ivid"],
            pbb_isid=self.mc_info_list[0]["pbb_isid"],
            bvid=-1).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        self.mocker.ReplayAll()

        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port, reply_type)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_receive_from_ryu(self):
        # 受信処理はdummyのメソッドに置き換える
        self.mld_proc.recv_sock = dummy_socket()

        # 無限ループを脱出して終了すること
        hub.spawn(self.mld_proc.receive_from_ryu)
        hub.sleep(1)
        self.mld_proc.RECV_LOOP = False
        hub.sleep(1)
        self.mld_proc.RECV_LOOP = True


# class test_user_manage():
#
#    mc_addr1 = "ff38::1:1"
#    mc_addr2 = "ff38::1:2"
#    serv_ip = "2001::1:20"
#    datapathid1 = 276595101184
#    datapathid2 = 276596903168
#    in_port1 = 1
#    in_port2 = 2
#
#    # このクラスのテストケースを実行する前に１度だけ実行する
#    @classmethod
#    def setup_class(cls):
#        logger.debug("setup")
#        cls.mocker = Mox()
#        cls.mld_proc = mld_process()
#
#    # このクラスのテストケースをすべて実行した後に１度だけ実行する
#    @classmethod
#    def teardown_class(cls):
#        logger.debug("teardown")
#
#    def setup(self):
#        # 設定値の初期化
#        self.mld_proc.ch_info.channel_info = {}
#        self.mld_proc.ch_info.user_info_list = []
#
#    def teardown(self):
#        pass
#
#    @attr(do=False)
#    def test_add_user_01(self):
#        pass


class dummy_socket():
    def recv(self):
        logger.debug("dummy recv...")
        dummydata = dispatch(type_=0, datapathid=0, data="dummy")
        return cPickle.dumps(dummydata)


if __name__ == '__main__':
    unittest.main()