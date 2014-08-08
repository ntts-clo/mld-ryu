# coding: utf-8
# nose install
#  >sudo pip install nose
# coverage install
#  >sudo pip install coverage
# mox install
#  >sudo pip install mox
#
import pdb
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

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
APP_PATH = DIR_PATH + "/../app/"
sys.path.append(APP_PATH)
import mld_process
from user_manage import channel_info

COMMON_PATH = DIR_PATH + "/../../common/"
sys.path.append(COMMON_PATH)
from zmq_dispatch import dispatch, packet_out_data
from read_json import read_json
import mld_const as const
from common.icmpv6_extend import icmpv6_extend, checksum_ip, checksum
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

        cls.mld_proc = mld_process.mld_process()

    # このクラスのテストケースをすべて実行した後に１度だけ実行する
    @classmethod
    def teardown_class(cls):
        logger.debug("teardown")

    def setup(self):
        self.mocker = Mox()
        # 設定値の初期化
        self.mld_proc.ch_info = channel_info(self.config)
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
    def test_init_check_url_true(self):
        logger.debug("")

        # 読み込む設定ファイルを変更(check_urlがTrueを返却)
        temp_common = mld_process.COMMON_PATH
        mld_process.COMMON_PATH = "./test_common/"
        temp_conf = const.CONF_FILE
        const.CONF_FILE = "config_ipc.json"

        mld_process.mld_process()

        # 変更した設定を元に戻す
        mld_process.COMMON_PATH = temp_common
        const.CONF_FILE = temp_conf

    @attr(do=False)
    def test_init_check_url_exception(self):
        # errorログが出力されることを机上で確認

        # 読み込む設定ファイルを変更(check_urlがTrueを返却)
        temp_common = mld_process.COMMON_PATH
        mld_process.COMMON_PATH = "./test_common/"
        temp_conf = const.CONF_FILE
        const.CONF_FILE = "config_other.json"

        mld_process.mld_process()

        # 変更した設定を元に戻す
        mld_process.COMMON_PATH = temp_common
        const.CONF_FILE = temp_conf

    @attr(do=False)
    def test_check_url_ipc(self):
        logger.debug("test_check_url_Success001")
        """
        概要：zmqで使用するurlの妥当性チェック
        条件：zmq_url=ipc://
        結果：resultがTrueであること
        """
        # 【前処理】
        zmq_url = "ipc://"

        # 【実行】
        result = self.mld_proc.check_url(zmq_url)

        # 【結果】
        logger.debug("test_check_url_Success001 [result] %s", str(result))
        ok_(result)

    @attr(do=False)
    def test_check_url_tcp(self):
        logger.debug("test_check_url_Success002")
        """
        概要：zmqで使用するurlの妥当性チェック
        条件：zmq_url=tcp://
        結果：resultがTrueであること
        """
        # 【前処理】
        zmq_url = "tcp://"

        # 【実行】
        result = self.mld_proc.check_url(zmq_url)

        # 【結果】
        logger.debug("test_check_url_Success002 [result] %s", str(result))
        ok_(not result)

    @attr(do=False)
    @raises(Exception)
    def test_check_url_other(self):
        logger.debug("test_check_url_Failer001")
        """
        概要：zmqで使用するurlの妥当性チェック
        条件：zmq_url=ipf:///
        結果：Exceptionが発生すること
        """
        # 【前処理】
        zmq_url = "ipf:///"
        # 【実行】
        result = self.mld_proc.check_url(zmq_url)
        # 【結果】
        logger.debug("test_check_url_other [Exception] %s", e)

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
        self.mld_proc.config["reguraly_query_interval"] = 6
        self.mld_proc.config["mc_query_interval"] = 1
        self.mld_proc.config["mld_esw_ifname"] = "eth0"

        send_hub = hub.spawn(self.mld_proc.send_mldquery_regularly)
        # ループに入る分処理待ち
        hub.sleep(5)
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
                self.mld_proc.send_packet_to_sw(
                    "sendpkt", mc_info["mc_addr"])
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
    def test_create_packet_query01(self):
        # MLD Queryを持つpacketを生成
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        vid = self.config["c_tag_id"]
        query = self.mld_proc.create_mldquery(mc_addr, serv_ip)
        actual = self.mld_proc.create_packet(
            self.addressinfo, vid, query)

        eth = actual.get_protocol(ethernet.ethernet)
        eq_(self.addressinfo[0], eth.src)
        eq_(self.mld_proc.QUERY_DST, eth.dst)

        vln = actual.get_protocol(vlan.vlan)
        eq_(vid, vln.vid)

        ip6 = actual.get_protocol(ipv6.ipv6)
        eq_(self.addressinfo[1], ip6.src)
        eq_(self.mld_proc.QUERY_DST_IP, ip6.dst)
        # 拡張ヘッダを持っていることを確認
        eq_(inet.IPPROTO_HOPOPTS, ip6.nxt)
        ok_(ip6.ext_hdrs)

        icmp6 = actual.get_protocol(icmpv6.icmpv6)
        eq_(icmpv6.MLD_LISTENER_QUERY, icmp6.type_)
        eq_(query, icmp6.data)

    @attr(do=False)
    @raises(Exception)
    def test_create_packet_query02(self):
        # MLD Queryを持つpacketを生成
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        vid = self.config["c_tag_id"]
        query = self.mld_proc.create_mldquery(mc_addr, serv_ip)

        query.version = 4

        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6, data=[
            ipv6.option(type_=5, len_=2, data="\x00\x00"),
            ipv6.option(type_=1, len_=0)])]

        checksum_ip(query, len(ext_headers),
                              icmpv6.MLD_LISTENER_QUERY, inet.IPPROTO_ICMPV6)

        logger.debug("test_create_packet_query02 [Exception] %s", e)

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

        eth = actual.get_protocol(ethernet.ethernet)
        eq_(self.addressinfo[0], eth.src)
        eq_(self.mld_proc.REPORT_DST, eth.dst)

        vln = actual.get_protocol(vlan.vlan)
        eq_(vid, vln.vid)

        ip6 = actual.get_protocol(ipv6.ipv6)
        eq_(self.addressinfo[1], ip6.src)
        eq_(self.mld_proc.REPORT_DST_IP, ip6.dst)
        # 拡張ヘッダを持っていることを確認
        eq_(inet.IPPROTO_HOPOPTS, ip6.nxt)
        ok_(ip6.ext_hdrs)

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
        self.mld_proc.send_packet_to_sw(packet, "ff38::1:1")

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
        self.mld_proc.reply_proxy(mc_addr, [serv_ip])
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
    @raises(Exception)
    def test_analyse_receive_packet_other(self):
        # それ以外のパケットを受信した場合：エラーログを出力
        dispatch_ = dispatch("test", 1)

        # logger.errorの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "error")
        self.mld_proc.logger.error(
            "dispatch[type_]:Not Exist(%s)", "test")
        self.mocker.ReplayAll()

        self.mld_proc.analyse_receive_packet(dispatch_)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_analyse_receive_packet_exception(self):
        # 解析中に例外が発生した場合：エラーログを出力
        dispatch_ = dispatch(const.CON_SWITCH_FEATURE, 1)

        # set_switch_configがExceptionを返却
        self.mocker.StubOutWithMock(self.mld_proc, "set_switch_config")
        self.mld_proc.set_switch_config(
            {'data': None, 'type_': 11, 'datapathid': 1,
             'in_port': -1, 'cid': 0}).AndRaise(Exception())

        # logger.errorの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "error")
        self.mld_proc.logger.error(IsA(str), None)
        self.mocker.ReplayAll()

        self.mld_proc.analyse_receive_packet(dispatch_)
        self.mocker.VerifyAll()

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

        # send_mldqueryをスタブ化
        mc_info = {"mc_addr": mc_addr1, "serv_ip": serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

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
        actual = self.mld_proc.reply_proxy("::", [])
        eq_(-1, actual)

    @attr(do=False)
    def test_reply_proxy_exists_user_gq(self):
        # 視聴情報がありGeneralQueryの場合、視聴中のmcアドレス分p-out
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

        self.mld_proc.reply_proxy("::", [])
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_reply_proxy_exists_user_sq_exists_user(self):
        # 視聴情報がありSpecificQuery場合、受信したmcアドレスが視聴中であればp-out
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

        # 受信したmc_addrを引数にcreate_mldreportが呼び出されることを確認
        report_type = [icmpv6.MODE_IS_INCLUDE]
        self.mocker.StubOutWithMock(self.mld_proc, "create_mldreport")
        self.mld_proc.create_mldreport(mc_addr1, serv_ip, report_type)

        self.mocker.StubOutWithMock(self.mld_proc, "create_packet")
        self.mld_proc.create_packet(IsA(list), IsA(int), None)

        self.mocker.StubOutWithMock(self.mld_proc, "create_packetout")
        self.mld_proc.create_packetout(
            datapathid=self.mld_proc.edge_switch["datapathid"], packet=None)

        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))
        self.mocker.ReplayAll()

        self.mld_proc.reply_proxy(mc_addr1, [serv_ip])
        self.mocker.VerifyAll()

    @attr(do=True)
    @raises(ExpectedMethodCallsError)
    def test_reply_proxy_exists_user_sq_no_user(self):
        # 視聴情報がありSpecificQuery場合、受信したmcアドレスが視聴中ででなければなにもしない
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

        # create_mldreportが呼び出されないことを確認
        self.mocker.StubOutWithMock(self.mld_proc, "create_mldreport")
        self.mld_proc.create_mldreport(IsA(str), IsA(str), IsA(list))
        self.mocker.ReplayAll()

        self.mld_proc.reply_proxy("ff38::1:2", [serv_ip])
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

        self.mocker.StubOutWithMock(self.mld_proc, "update_user_info")
        self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid,
            icmpv6.MODE_IS_INCLUDE).AndReturn(const.CON_REPLY_NOTHING)
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

        # update_user_infoがCON_REPLY_ADD_MC_GROUPを返却
        self.mocker.StubOutWithMock(self.mld_proc, "update_user_info")
        self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid,
            icmpv6.MODE_IS_INCLUDE).AndReturn(const.CON_REPLY_ADD_MC_GROUP)

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

        # update_ch_infoの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.ch_info, "update_ch_info")
        self.mld_proc.ch_info.update_ch_info(
            mc_addr=mc_addr, serv_ip=serv_ip, datapathid=datapathid,
            port_no=in_port, cid=cid).AndReturn(const.CON_REPLY_NOTHING)
        self.mocker.ReplayAll()

        actual = self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid,
            icmpv6.ALLOW_NEW_SOURCES)
        eq_(const.CON_REPLY_NOTHING, actual)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_update_user_info_block(self):
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:20"
        datapathid = self.mld_proc.switches[1]["datapathid"]
        in_port = 1
        cid = 100

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
            mc_addr, serv_ip, datapathid, in_port, cid,
            icmpv6.BLOCK_OLD_SOURCES)
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

        # update_ch_infoの呼び出し確認がCON_REPLY_NOTHINGを返す
        self.mocker.StubOutWithMock(
            self.mld_proc.ch_info, "update_ch_info")
        self.mld_proc.ch_info.update_ch_info(
            mc_addr=mc_addr, serv_ip=serv_ip, datapathid=datapathid,
            port_no=in_port, cid=cid).AndReturn(const.CON_REPLY_NOTHING)
        self.mocker.ReplayAll()

        actual = self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid, icmpv6.MODE_IS_INCLUDE)
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

        for type_ in types:
            actual = self.mld_proc.update_user_info(
                mc_addr, serv_ip, datapathid, in_port, cid, type_)
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


class test_user_manage():

    mc_addr1 = "ff38::1:1"
    mc_addr2 = "ff38::1:2"
    serv_ip = "2001::1:20"
    datapathid1 = 276595101184
    datapathid2 = 276596903168
    in_port1 = 1
    in_port2 = 2

    # このクラスのテストケースを実行する前に１度だけ実行する
    @classmethod
    def setup_class(cls):
        logger.debug("setup")
        config = read_json(COMMON_PATH + const.CONF_FILE)
        cls.config = config.data["settings"]
        cls.mld_proc = mld_process.mld_process()

    # このクラスのテストケースをすべて実行した後に１度だけ実行する
    @classmethod
    def teardown_class(cls):
        logger.debug("teardown")

    def setup(self):
        self.mocker = Mox()
        # 設定値の初期化
        self.mld_proc.ch_info = channel_info(self.config)
        self.mld_proc.config = self.config

    def teardown(self):
        self.mocker.UnsetStubs()

    @attr(do=False)
    def test_add_user_01(self):
        # 視聴開始（初回ユーザ参加）
        #   update_user_infoの返却値がCON_REPLY_ADD_MC_GROUPであること
        #   視聴情報が1件追加されていること

        # 事前状態確認
        eq_({}, self.mld_proc.ch_info.channel_info)
        eq_([], self.mld_proc.ch_info.user_info_list)

        cid = 1111
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.ALLOW_NEW_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_ADD_MC_GROUP, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(1, len(self.mld_proc.ch_info.channel_info.keys()))
        eq_((self.mc_addr1, self.serv_ip),
            self.mld_proc.ch_info.channel_info.keys()[0])
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr1, self.serv_ip]
        eq_(1, len(sw_info.keys()))
        eq_(self.datapathid1, sw_info.keys()[0])
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no, cid)
        eq_(1, len(ch_sw_info.port_info.keys()))
        eq_(self.in_port1, ch_sw_info.port_info.keys()[0])
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(1, len(user_info.keys()))
        eq_(cid, user_info.keys()[0])
        ch_user_info = user_info[cid]

        # channel_user_info(cid)
        eq_(cid, ch_user_info.cid)
        regist_time = ch_user_info.time

        # user_info_list
        #   リストに追加されていること
        eq_(1, len(self.mld_proc.ch_info.user_info_list))
        ch_user_info = self.mld_proc.ch_info.user_info_list[-1]
        eq_(cid, ch_user_info.cid)
        eq_(regist_time, ch_user_info.time)

    @attr(do=False)
    def test_add_user_02(self):
        # 視聴開始（ポート内にユーザ既存）
        #   update_user_infoの返却値がCON_REPLY_NOTHINGであること
        #   既存の視聴情報にさらにユーザが1件追加されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        eq_(1, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)

        cid = 1112
        # 新規ユーザ
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.ALLOW_NEW_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_NOTHING, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(1, len(self.mld_proc.ch_info.channel_info.keys()))
        eq_((self.mc_addr1, self.serv_ip),
            self.mld_proc.ch_info.channel_info.keys()[0])
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr1, self.serv_ip]
        eq_(1, len(sw_info.keys()))
        eq_(self.datapathid1, sw_info.keys()[0])
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        eq_(1, len(ch_sw_info.port_info.keys()))
        eq_(self.in_port1, ch_sw_info.port_info.keys()[0])
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(2, len(user_info.keys()))
        ok_(cid in user_info)
        ch_user_info = user_info[cid]

        # channel_user_info(cid)
        eq_(cid, ch_user_info.cid)
        regist_time = ch_user_info.time

        # user_info_list
        #   リストの末尾に追加されていること
        eq_(2, len(self.mld_proc.ch_info.user_info_list))
        ch_user_info = self.mld_proc.ch_info.user_info_list[-1]
        eq_(cid, ch_user_info.cid)
        eq_(regist_time, ch_user_info.time)

    @attr(do=False)
    def test_add_user_03(self):
        # 視聴開始（ポートで初回）
        #   update_user_infoの返却値がCON_REPLY_ADD_PORTであること
        #   既存の視聴情報にポートが1件追加されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        eq_(2, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)

        cid = 1121
        # 新規ポート
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2,
            cid, icmpv6.ALLOW_NEW_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_ADD_PORT, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(1, len(self.mld_proc.ch_info.channel_info.keys()))
        eq_((self.mc_addr1, self.serv_ip),
            self.mld_proc.ch_info.channel_info.keys()[0])
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr1, self.serv_ip]
        eq_(1, len(sw_info.keys()))
        eq_(self.datapathid1, sw_info.keys()[0])
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        eq_(2, len(ch_sw_info.port_info.keys()))
        ok_(self.in_port2 in ch_sw_info.port_info)
        user_info = ch_sw_info.port_info[self.in_port2]
        eq_(1, len(user_info.keys()))
        eq_(cid, user_info.keys()[0])
        ch_user_info = user_info[cid]

        # channel_user_info(cid)
        eq_(cid, ch_user_info.cid)
        regist_time = ch_user_info.time

        # user_info_list
        #   リストの末尾に追加されていること
        eq_(3, len(self.mld_proc.ch_info.user_info_list))
        ch_user_info = self.mld_proc.ch_info.user_info_list[-1]
        eq_(cid, ch_user_info.cid)
        eq_(regist_time, ch_user_info.time)

    @attr(do=False)
    def test_add_user_04(self):
        # 視聴開始（SWで初回）
        #   update_user_infoの返却値がCON_REPLY_ADD_SWITCHであること
        #   既存の視聴情報にSWが1件追加されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2, 1121)
        eq_(3, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[2].cid)

        cid = 1211
        # 新規ポート
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1,
            cid, icmpv6.ALLOW_NEW_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_ADD_SWITCH, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(1, len(self.mld_proc.ch_info.channel_info.keys()))
        eq_((self.mc_addr1, self.serv_ip),
            self.mld_proc.ch_info.channel_info.keys()[0])
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr1, self.serv_ip]
        eq_(2, len(sw_info.keys()))
        ok_(self.datapathid2 in sw_info)
        ch_sw_info = sw_info[self.datapathid2]

        # channel_switch_info(port_no)
        eq_(1, len(ch_sw_info.port_info.keys()))
        eq_(self.in_port1, ch_sw_info.port_info.keys()[0])
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(1, len(user_info.keys()))
        eq_(cid, user_info.keys()[0])
        ch_user_info = user_info[cid]

        # channel_user_info(cid)
        eq_(cid, ch_user_info.cid)
        regist_time = ch_user_info.time

        # user_info_list
        #   リストの末尾に追加されていること
        eq_(4, len(self.mld_proc.ch_info.user_info_list))
        ch_user_info = self.mld_proc.ch_info.user_info_list[-1]
        eq_(cid, ch_user_info.cid)
        eq_(regist_time, ch_user_info.time)

    @attr(do=False)
    def test_add_user_05(self):
        # 視聴開始（MCで初回）
        #   update_user_infoの返却値がCON_REPLY_ADD_MC_GROUPであること
        #   既存の視聴情報にMCが1件追加されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2, 1121)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1, 1211)
        eq_(4, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[3].cid)

        cid = 2111
        # 新規MCアドレス
        actual = self.mld_proc.update_user_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.ALLOW_NEW_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_ADD_MC_GROUP, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(2, len(self.mld_proc.ch_info.channel_info.keys()))
        ok_((self.mc_addr2, self.serv_ip)
            in self.mld_proc.ch_info.channel_info)
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr2, self.serv_ip]
        eq_(1, len(sw_info.keys()))
        eq_(self.datapathid1, sw_info.keys()[0])
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        eq_(1, len(ch_sw_info.port_info.keys()))
        eq_(self.in_port1, ch_sw_info.port_info.keys()[0])
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(1, len(user_info.keys()))
        eq_(cid, user_info.keys()[0])
        ch_user_info = user_info[cid]

        # channel_user_info(cid)
        eq_(cid, ch_user_info.cid)
        regist_time = ch_user_info.time

        # user_info_list
        #   リストの末尾に追加されていること
        eq_(5, len(self.mld_proc.ch_info.user_info_list))
        ch_user_info = self.mld_proc.ch_info.user_info_list[-1]
        eq_(cid, ch_user_info.cid)
        eq_(regist_time, ch_user_info.time)

    @attr(do=False)
    def test_add_user_06(self):
        # 視聴開始（ALLOWが受信できなかったユーザ）
        #   update_user_infoの返却値がCON_REPLY_NOTHINGであること
        #   既存の視聴情報にユーザが1件追加されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2, 1121)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1, 1211)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 2111)
        eq_(5, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[3].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[4].cid)

        # 既存のcidと同一
        cid = 1112
        # 新規ユーザ（MODE_IS_INCLUDE）
        actual = self.mld_proc.update_user_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.MODE_IS_INCLUDE)

        # 返却値の確認
        eq_(const.CON_REPLY_NOTHING, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(2, len(self.mld_proc.ch_info.channel_info.keys()))
        ok_((self.mc_addr2, self.serv_ip)
            in self.mld_proc.ch_info.channel_info)
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr2, self.serv_ip]
        eq_(1, len(sw_info.keys()))
        eq_(self.datapathid1, sw_info.keys()[0])
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        eq_(1, len(ch_sw_info.port_info.keys()))
        eq_(self.in_port1, ch_sw_info.port_info.keys()[0])
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(2, len(user_info.keys()))
        ok_(cid in user_info)
        ch_user_info = user_info[cid]

        # channel_user_info(cid)
        eq_(cid, ch_user_info.cid)
        regist_time = ch_user_info.time

        # user_info_list
        #   リストの末尾に追加されていること
        eq_(6, len(self.mld_proc.ch_info.user_info_list))
        ch_user_info = self.mld_proc.ch_info.user_info_list[-1]
        eq_(cid, ch_user_info.cid)
        eq_(regist_time, ch_user_info.time)

    @attr(do=False)
    def test_update_user_01(self):
        # 視聴継続（既存ユーザに対するINCLUDE）
        #   update_user_infoの返却値がCON_REPLY_NOTHINGであること
        #   既存のユーザ情報が1件更新されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2, 1121)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1, 1211)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 2111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        eq_(6, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[3].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[4].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[5].cid)

        cid = 2111
        # 更新前timeの取り出し
        bf_time = self.mld_proc.ch_info.user_info_list[1].time
        # 既存ユーザに対するALLOW_NEW_SOURCES
        actual = self.mld_proc.update_user_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.MODE_IS_INCLUDE)

        # 返却値の確認
        eq_(const.CON_REPLY_NOTHING, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(2, len(self.mld_proc.ch_info.channel_info.keys()))
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr2, self.serv_ip]
        eq_(1, len(sw_info.keys()))
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        eq_(1, len(ch_sw_info.port_info.keys()))
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(2, len(user_info.keys()))
        ch_user_info = user_info[cid]

        # channel_user_info(cid)
        eq_(cid, ch_user_info.cid)
        regist_time = ch_user_info.time
        # timeが更新されていること
        ok_(bf_time < regist_time)

        # user_info_list
        #   更新されたユーザがリストの末尾に移動していること
        eq_(6, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[3].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[4].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[5].cid)

        ch_user_info = self.mld_proc.ch_info.user_info_list[-1]
        eq_(cid, ch_user_info.cid)
        eq_(regist_time, ch_user_info.time)

    @attr(do=False)
    def test_update_user_02(self):
        # 視聴継続（既存ユーザに対するALLOW）
        #   update_user_infoの返却値がCON_REPLY_NOTHINGであること
        #   既存のユーザ情報が1件更新されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2, 1121)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1, 1211)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 2111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        eq_(6, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[3].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[4].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[5].cid)

        cid = 1111
        # 更新前timeの取り出し
        bf_time = self.mld_proc.ch_info.user_info_list[1].time
        # 既存ユーザに対するALLOW_NEW_SOURCES
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.ALLOW_NEW_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_NOTHING, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(2, len(self.mld_proc.ch_info.channel_info.keys()))
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr1, self.serv_ip]
        eq_(2, len(sw_info.keys()))
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        eq_(2, len(ch_sw_info.port_info.keys()))
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(2, len(user_info.keys()))
        ch_user_info = user_info[cid]

        # channel_user_info(cid)
        eq_(cid, ch_user_info.cid)
        regist_time = ch_user_info.time
        # timeが更新されていること
        ok_(bf_time < regist_time)

        # user_info_list
        #   更新されたユーザがリストの末尾に移動していること
        eq_(6, len(self.mld_proc.ch_info.user_info_list))
        eq_(1112, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[3].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[4].cid)
        eq_(1111, self.mld_proc.ch_info.user_info_list[5].cid)

        ch_user_info = self.mld_proc.ch_info.user_info_list[-1]
        eq_(cid, ch_user_info.cid)
        eq_(regist_time, ch_user_info.time)

    @attr(do=False)
    def test_remove_user_01(self):
        # 視聴終了（ポート内にユーザ残存）
        #   update_user_infoの返却値がCON_REPLY_NOTHINGであること
        #   既存のユーザ情報が1件削除されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2, 1121)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1, 1211)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 2111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        eq_(6, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[3].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[4].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[5].cid)

        # send_mldqueryをスタブ化
        mc_info = {"mc_addr": self.mc_addr1, "serv_ip": self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        cid = 1112
        # ユーザの削除
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.BLOCK_OLD_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_NOTHING, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(2, len(self.mld_proc.ch_info.channel_info.keys()))
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr1, self.serv_ip]
        eq_(2, len(sw_info.keys()))
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        #   cidに対応するユーザが存在しないこと
        eq_(2, len(ch_sw_info.port_info.keys()))
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(1, len(user_info.keys()))
        ok_(cid not in user_info)

        # user_info_list
        #   ユーザが削除されていること
        eq_(5, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[3].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[4].cid)

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_remove_user_02(self):
        # 視聴終了（ポート最終、SWにユーザ残存）
        #   update_user_infoの返却値がCON_REPLY_DEL_PORTであること
        #   既存のポート情報が1件削除されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2, 1121)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1, 1211)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 2111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        eq_(5, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[3].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[4].cid)

        # send_mldqueryをスタブ化
        mc_info = {"mc_addr": self.mc_addr1, "serv_ip": self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        cid = 1111
        # ユーザの削除(ポート削除)
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.BLOCK_OLD_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_DEL_PORT, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(2, len(self.mld_proc.ch_info.channel_info.keys()))
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr1, self.serv_ip]
        eq_(2, len(sw_info.keys()))
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        #   in_port1に対応するポートが存在しないこと
        eq_(1, len(ch_sw_info.port_info.keys()))
        ok_(self.in_port1 not in ch_sw_info.port_info)

        # user_info_list
        #   ユーザが削除されていること
        eq_(4, len(self.mld_proc.ch_info.user_info_list))
        eq_(1121, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[3].cid)

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_remove_user_03(self):
        # 視聴終了（SWで最終）
        #   update_user_infoの返却値がCON_REPLY_DEL_SWITCHであること
        #   既存のSW情報が1件削除されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2, 1121)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1, 1211)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 2111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        eq_(4, len(self.mld_proc.ch_info.user_info_list))
        eq_(1121, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[3].cid)

        # send_mldqueryをスタブ化
        mc_info = {"mc_addr": self.mc_addr1, "serv_ip": self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        cid = 1211
        # ユーザの削除(SW削除)
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1,
            cid, icmpv6.BLOCK_OLD_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_DEL_SWITCH, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        #   datapathid2に対応するSWが存在しないこと
        eq_(2, len(self.mld_proc.ch_info.channel_info.keys()))
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr1, self.serv_ip]
        eq_(1, len(sw_info.keys()))
        ok_(self.datapathid2 not in sw_info)

        # user_info_list
        #   ユーザが削除されていること
        eq_(3, len(self.mld_proc.ch_info.user_info_list))
        eq_(1121, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[2].cid)

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_remove_user_04(self):
        # 視聴終了（MCで最終）
        #   update_user_infoの返却値がCON_REPLY_DEL_MC_GROUPであること
        #   既存のMC情報が1件削除されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2, 1121)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 2111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        eq_(3, len(self.mld_proc.ch_info.user_info_list))
        eq_(1121, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[2].cid)

        # send_mldqueryをスタブ化
        mc_info = {"mc_addr": self.mc_addr1, "serv_ip": self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        cid = 1121
        # ユーザの削除(MC削除)
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2,
            cid, icmpv6.BLOCK_OLD_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_DEL_MC_GROUP, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        #   対応するMCアドレスが存在しないこと
        eq_(1, len(self.mld_proc.ch_info.channel_info.keys()))
        ok_((self.mc_addr1, self.serv_ip)
            not in self.mld_proc.ch_info.channel_info)

        # user_info_list
        #   ユーザが削除されていること
        eq_(2, len(self.mld_proc.ch_info.user_info_list))
        eq_(2111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_remove_user_05(self):
        # 視聴終了（未登録のユーザに対するBLOCK）
        #   update_user_infoの返却値がCON_REPLY_NOTHINGであること
        #   視聴情報が更新されていないこと

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 2111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        eq_(2, len(self.mld_proc.ch_info.user_info_list))
        eq_(2111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)
        bf_time1 = self.mld_proc.ch_info.user_info_list[0].time
        bf_time2 = self.mld_proc.ch_info.user_info_list[1].time

        cid = 1121
        # 削除対象ユーザなし
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2,
            cid, icmpv6.BLOCK_OLD_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_NOTHING, actual)

        # user_info_list
        #   更新されていないこと
        eq_(2, len(self.mld_proc.ch_info.user_info_list))
        eq_(2111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(bf_time1, self.mld_proc.ch_info.user_info_list[0].time)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(bf_time2, self.mld_proc.ch_info.user_info_list[1].time)

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_remove_user_06(self):
        # 視聴終了（最終ユーザ）
        #   update_user_infoの返却値がCON_REPLY_DEL_MC_GROUPであること
        #   視聴情報が全て削除されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 2111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        eq_(2, len(self.mld_proc.ch_info.user_info_list))
        eq_(2111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)

        # send_mldqueryをスタブ化
        mc_info = {"mc_addr": self.mc_addr2, "serv_ip": self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        cid1 = 1112
        # ユーザの削除
        actual = self.mld_proc.update_user_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1,
            cid1, icmpv6.BLOCK_OLD_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_NOTHING, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(1, len(self.mld_proc.ch_info.channel_info.keys()))
        eq_((self.mc_addr2, self.serv_ip),
            self.mld_proc.ch_info.channel_info.keys()[0])
        sw_info = self.mld_proc.ch_info.channel_info[
            (self.mc_addr2, self.serv_ip)]
        eq_(1, len(sw_info.keys()))
        eq_(self.datapathid1, sw_info.keys()[0])
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        #   cidに対応するユーザが存在しないこと
        eq_(1, len(ch_sw_info.port_info.keys()))
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(1, len(user_info.keys()))
        ok_(cid1 not in user_info)

        # user_info_list
        #   ユーザが削除されていること
        eq_(1, len(self.mld_proc.ch_info.user_info_list))
        eq_(2111, self.mld_proc.ch_info.user_info_list[0].cid)

        cid2 = 2111
        # ユーザの削除(MC削除)
        actual = self.mld_proc.update_user_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1,
            cid2, icmpv6.BLOCK_OLD_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_DEL_MC_GROUP, actual)

        # channel_info(mc_addr, serv_ip, datapathid)
        #   視聴情報が存在しないこと
        eq_({}, self.mld_proc.ch_info.channel_info)

        # user_info_list
        #   ユーザが削除されていること
        eq_([], self.mld_proc.ch_info.user_info_list)

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_timeout_01(self):
        # 視聴終了（タイムアウト）
        #   mld_queryがpacket-inした契機でタイムアウトチェックが発生し、
        #   タイムアウトとなったユーザ情報が削除されていること

        # 事前準備
        self.mld_proc.config["user_time_out"] = 3

        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)

        eq_(1, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)

        # reply_proxyの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "reply_proxy")
        self.mld_proc.reply_proxy(self.mc_addr1, [self.serv_ip])

        # send_mldqueryの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        mc_info = {"mc_addr": self.mc_addr1, "serv_ip": self.serv_ip}
        self.mld_proc.send_mldquery([mc_info])

        # reply_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "reply_to_ryu")
        self.mld_proc.reply_to_ryu(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            const.CON_REPLY_DEL_MC_GROUP)

        self.mocker.ReplayAll()

        # packet-inしたデータを作成
        query = self.mld_proc.create_mldquery(self.mc_addr1, self.serv_ip)
        data = icmpv6.icmpv6(
            type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY, data=query)
        dispatch_ = dispatch(const.CON_PACKET_IN, 1, data=data)

        # タイムアウトを発生させるため処理待ち
        hub.sleep(3)

        self.mld_proc.analyse_receive_packet(dispatch_)

        # channel_info(mc_addr, serv_ip, datapathid)
        #   視聴情報が存在しないこと
        eq_({}, self.mld_proc.ch_info.channel_info)

        # user_info_list
        #   ユーザが削除されていること
        eq_([], self.mld_proc.ch_info.user_info_list)

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_timeout_02(self):
        # 視聴継続&視聴終了（タイムアウト）
        #   mld_reportがpacket-inした契機でタイムアウトチェックが発生し、
        #   タイムアウトとなったユーザ情報が削除されていること

        # 事前準備
        temp_timeout = self.mld_proc.config["user_time_out"]
        self.mld_proc.config["user_time_out"] = 3

        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1112)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2, 1121)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1, 1211)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 2111)
        # タイムアウトを発生させるため処理待ち
        hub.sleep(3)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 1112)

        eq_(6, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[1].cid)
        eq_(1121, self.mld_proc.ch_info.user_info_list[2].cid)
        eq_(1211, self.mld_proc.ch_info.user_info_list[3].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[4].cid)
        eq_(1112, self.mld_proc.ch_info.user_info_list[5].cid)

        # send_mldqueryをスタブ化
        mc_info = {"mc_addr": self.mc_addr1, "serv_ip": self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")

        # reply_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "reply_to_ryu")

        #   cid:1211の削除後
        self.mld_proc.send_mldquery([mc_info])
        self.mld_proc.reply_to_ryu(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1,
            const.CON_REPLY_DEL_SWITCH)

        #   cid:1121の削除後
        self.mld_proc.send_mldquery([mc_info])
        self.mld_proc.reply_to_ryu(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2,
            const.CON_REPLY_DEL_PORT)

        #   cid:1112の削除後
        self.mld_proc.reply_to_ryu(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            const.CON_REPLY_NOTHING)

        #   cid:1111の削除後
        self.mld_proc.send_mldquery([mc_info])
        self.mld_proc.reply_to_ryu(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            const.CON_REPLY_DEL_MC_GROUP)
        self.mld_proc.send_mldquery([mc_info])

        # packet-inしたデータを作成
        cid = 2111
        types = [icmpv6.MODE_IS_INCLUDE]
        mld = self.mld_proc.create_mldreport(
            self.mc_addr2, self.serv_ip, types)
        data = icmpv6.icmpv6(
            type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)
        dispatch_ = dispatch(
            const.CON_PACKET_IN, self.datapathid1, self.in_port1, cid, data)

        # 更新前timeの取り出し
        bf_time = self.mld_proc.ch_info.user_info_list[4].time

        self.mld_proc.analyse_receive_packet(dispatch_)

        # channel_info(mc_addr, serv_ip, datapathid)
        #   mc_addr1は削除されていること
        eq_(1, len(self.mld_proc.ch_info.channel_info.keys()))
        ok_((self.mc_addr1, self.serv_ip)
            not in self.mld_proc.ch_info.channel_info)
        eq_((self.mc_addr2, self.serv_ip),
            self.mld_proc.ch_info.channel_info.keys()[0])
        sw_info = self.mld_proc.ch_info.channel_info[
            (self.mc_addr2, self.serv_ip)]
        eq_(1, len(sw_info.keys()))
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        eq_(1, len(ch_sw_info.port_info.keys()))
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(2, len(user_info.keys()))
        ch_user_info = user_info[cid]

        # channel_user_info(cid)
        eq_(cid, ch_user_info.cid)
        regist_time = ch_user_info.time
        # timeが更新されていること
        ok_(bf_time < regist_time)

        # user_info_list
        #   更新されたユーザがリストの末尾に移動していること
        eq_(2, len(self.mld_proc.ch_info.user_info_list))
        eq_(1112, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(2111, self.mld_proc.ch_info.user_info_list[1].cid)

        ch_user_info = self.mld_proc.ch_info.user_info_list[-1]
        eq_(cid, ch_user_info.cid)
        eq_(regist_time, ch_user_info.time)

        self.mld_proc.config["user_time_out"] = temp_timeout

    @attr(do=False)
    def test_no_db_regist(self):
        # 視聴開始（初回ユーザ参加）を行うが、DB登録は行わない
        #   DatabaseAccessor.clientがNoneのままであること

        # 読み込む設定ファイルを変更(check_urlがTrueを返却)
        temp_common = mld_process.COMMON_PATH
        mld_process.COMMON_PATH = "./test_common/"
        temp_conf = const.CONF_FILE
        const.CONF_FILE = "config_nodb.json"

        mld_proc = mld_process.mld_process()

        # 事前状態確認
        eq_({}, mld_proc.ch_info.channel_info)
        eq_([], mld_proc.ch_info.user_info_list)
        eq_(None, mld_proc.ch_info.accessor.client)

        cid = 1111
        actual = mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.ALLOW_NEW_SOURCES)

        # 返却値の確認
        eq_(const.CON_REPLY_ADD_MC_GROUP, actual)

        # clientはNoneのままであること
        eq_(None, mld_proc.ch_info.accessor.client)

        # 視聴情報の更新はされていること
        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(1, len(mld_proc.ch_info.channel_info.keys()))
        eq_((self.mc_addr1, self.serv_ip),
            mld_proc.ch_info.channel_info.keys()[0])
        sw_info = mld_proc.ch_info.channel_info[
            self.mc_addr1, self.serv_ip]
        eq_(1, len(sw_info.keys()))
        eq_(self.datapathid1, sw_info.keys()[0])
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no, cid)
        eq_(1, len(ch_sw_info.port_info.keys()))
        eq_(self.in_port1, ch_sw_info.port_info.keys()[0])
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(1, len(user_info.keys()))
        eq_(cid, user_info.keys()[0])
        ch_user_info = user_info[cid]

        # channel_user_info(cid)
        eq_(cid, ch_user_info.cid)
        regist_time = ch_user_info.time

        # user_info_list
        #   リストに追加されていること
        eq_(1, len(mld_proc.ch_info.user_info_list))
        ch_user_info = mld_proc.ch_info.user_info_list[-1]
        eq_(cid, ch_user_info.cid)
        eq_(regist_time, ch_user_info.time)

        # 変更した設定を元に戻す
        mld_process.COMMON_PATH = temp_common
        const.CONF_FILE = temp_conf


class dummy_socket():
    def recv(self):
        logger.debug("dummy recv...")
        dummydata = dispatch(type_=0, datapathid=0, data="dummy")
        return cPickle.dumps(dummydata)


if __name__ == '__main__':
    unittest.main()