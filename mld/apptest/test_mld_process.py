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
import threading
import logging
import logging.config
import unittest
import time
import ctypes
import cPickle
from mox import Mox, ExpectedMethodCallsError, IsA
from nose.tools import ok_, eq_
from nose.tools.nontrivial import raises
from nose.plugins.attrib import attr
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.ofproto import ofproto_v1_3,  ether, inet
from multiprocessing import Value

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
APP_PATH = DIR_PATH + "/../app/"
sys.path.append(APP_PATH)
import mld_process
import user_manage
from user_manage import channel_info

COMMON_PATH = DIR_PATH + "/../../common/"
sys.path.append(COMMON_PATH)
import mld_const as const
from zmq_dispatch import dispatch, packet_out_data
from read_json import read_json
from icmpv6_extend import icmpv6_extend, checksum_ip

TEST_COMMON_PATH = DIR_PATH + "/test_common/"

logging.config.fileConfig(TEST_COMMON_PATH + const.MLD_LOG_CONF)
logger = logging.getLogger(__name__)


class test_mld_process():

    # 実際に実行するマシンのIFに合わせた値を設定すること
    IFNAME = "eth0"
    MAC = "6c:3b:e5:51:1e:e4"
    IP6 = "fe80::6e3b:e5ff:fe51:1ee4"

    #MAC = "d4:3d:7e:4a:43:fd"
    #IP6 = "fe80::d63d:7eff:fe4a:43fd"

    #MAC = "8c:89:a5:db:c4:19"
    #IP6 = "fe80::8e89:a5ff:fedb:c419"

    # このクラスのテストケースを実行する前に１度だけ実行する
    @classmethod
    def setup_class(cls):
        logger.debug("setup_class")

        config = read_json(TEST_COMMON_PATH + const.CONF_FILE)
        cls.config = config.data[const.SETTING]
        cls.config_zmq_ipc = config.data[const.ZMQ_IPC]
        cls.config_zmq_tcp = config.data[const.ZMQ_TCP]

        mc_info = read_json(TEST_COMMON_PATH + const.MULTICAST_INFO)
        cls.mc_info_list = mc_info.data[const.MC_TAG_MC_INFO]

        # テスト用の設定ファイルを読み込ませる
        mld_process.COMMON_PATH = TEST_COMMON_PATH
        cls.mld_proc = mld_process.mld_process()

    def setup(self):
        self.mocker = Mox()

    def teardown(self):
        self.mocker.UnsetStubs()
        # 設定値の初期化
        self.mld_proc.SEND_LOOP = True
        self.mld_proc.RECV_LOOP = True
        self.mld_proc.ch_info = channel_info(self.config)
        self.mld_proc.config = self.config

    @attr(do="False")
    def test_init(self):
        # ロガーの設定
        ok_(self.mld_proc.logger)

        # 視聴情報初期化
        ok_(self.mld_proc.ch_info)

        # 設定情報読み込み
        eq_(self.mld_proc.config, self.config)

        # アドレス情報
        ok_(self.mld_proc.ifinfo)

        # スイッチ情報読み込み
        switches = read_json(TEST_COMMON_PATH + const.SWITCH_INFO)
        eq_(self.mld_proc.switch_mld_info,
            switches.data[const.SW_TAG_MLD_INFO])
        eq_(self.mld_proc.switch_mc_info,
            switches.data[const.SW_TAG_MC_INFO])
        eq_(self.mld_proc.switches, switches.data[const.SW_TAG_SWITCHES])

        # マルチキャスト情報読み込み
        eq_(self.mld_proc.mc_info_list, self.mc_info_list)
        ok_(self.mld_proc.mc_info_dict)

        # bvidパターン読み込み
        ok_(self.mld_proc.bvid_variation)

        # ZeroMQ送受信用設定
        zmq_url = self.config[const.ZMQ_TYPE].lower() + const.URL_DELIMIT
        eq_(self.mld_proc.zmq_pub, zmq_url +
            self.config_zmq_ipc[const.ZMQ_PUB])
        eq_(self.mld_proc.zmq_sub, zmq_url +
            self.config_zmq_ipc[const.ZMQ_SUB])

        # ZeroMQ送受信用設定
        ok_(self.mld_proc.send_sock)
        ok_(self.mld_proc.recv_sock)

        # Flowmod生成用インスタンス
        ok_(self.mld_proc.flowmod_gen)

    @attr(do="False")
    def test_init_get_zmq_connect_exception(self):
        # 読み込む設定ファイルを変更(check_zmq_typeがTrueを返却)
        temp_conf = const.CONF_FILE
        const.CONF_FILE = "config_other.json"

        # errorの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "error")
        self.mld_proc.logger.error(IsA(str), const.ZMQ_TYPE, "udp")
        self.mld_proc.logger.error(IsA(str), None)
        self.mocker.ReplayAll()

        try:
            mld_process.mld_process()
        except SystemExit:
            self.mocker.VerifyAll()
        finally:
            # 変更した設定を元に戻す
            const.CONF_FILE = temp_conf

    @attr(do=False)
    def test_get_interface_info(self):
        actual = self.mld_proc.get_interface_info(self.IFNAME)

        eq_(self.MAC, actual["mac"])
        eq_(self.IP6, actual["ip6"])

    @attr(do=False)
    @raises(SystemExit)
    def test_get_interface_info_no_exist_if1(self):
        # 引数に存在しないIF名を入力する
        ifname = "eth100"

        # error呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "error")
        self.mld_proc.logger.error(
            "input exist network interface name where " +
            const.CONF_FILE + " at 'mld_esw_ifname'.")
        self.mocker.ReplayAll()

        self.mld_proc.get_interface_info(ifname)
        self.mocker.VerifyAll()

    @attr(do=False)
    @raises(SystemExit)
    def test_get_interface_info_no_exist_if2(self):
        # 引数に"eth"を入力する
        #   ifconfigの起動には成功するが存在しないIFを指定した場合の確認
        ifname = "eth"

        # error呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "error")
        self.mld_proc.logger.error(
            "input exist network interface name where " +
            const.CONF_FILE + " at 'mld_esw_ifname'.")

        self.mld_proc.get_interface_info(ifname)
        self.mocker.VerifyAll()

    @attr(do=False)
    @raises(SystemExit)
    def test_get_interface_info_no_mac(self):
        # 引数にMACアドレスの存在しないIF（lo）を入力する
        ifname = "lo"

        # error呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "error")
        self.mld_proc.logger.error(
            "input network interface name with mac address where "
            + const.CONF_FILE + " at 'mld_esw_ifname'.")
        self.mocker.ReplayAll()

        self.mld_proc.get_interface_info(ifname)
        self.mocker.VerifyAll()

    @attr(do=False)
    @raises(SystemExit)
    def test_get_interface_info_no_ip6(self):
        # 引数にIPv6アドレスの存在しないIFを入力する
        #   存在しない場合はこのケースごとコメントアウトすること
        ifname = "virbr0"

        # error呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "error")
        self.mld_proc.logger.error(
            "input network interface name with " +
            "ipv6 link local address where " + const.CONF_FILE +
            " at 'mld_esw_ifname'.")
        self.mocker.ReplayAll()

        self.mld_proc.get_interface_info(ifname)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_calculate_qqic_under128(self):
        # 引数が128より小さい場合は値をそのまま返却する
        arg = 127
        actual = self.mld_proc.calculate_qqic(arg)
        eq_(arg, actual)

        arg = 1
        actual = self.mld_proc.calculate_qqic(arg)
        eq_(arg, actual)

    @attr(do=False)
    def test_calculate_qqic_over128(self):
        # 引数が128以上の場合は浮動小数として経産した結果を返却する
        arg = 128
        actual = self.mld_proc.calculate_qqic(arg)

        exp = 0
        while ((arg >> (exp + 3)) > 0x1f):
            exp = exp + 1
        mant = (arg >> (exp + 3)) & 0xf
        expect = 0x80 | (exp << 4) | mant
        eq_(expect, actual)

        arg = 1024
        actual = self.mld_proc.calculate_qqic(arg)

        exp = 0
        while ((arg >> (exp + 3)) > 0x1f):
            exp = exp + 1
        mant = (arg >> (exp + 3)) & 0xf
        expect = 0x80 | (exp << 4) | mant
        eq_(expect, actual)

    @attr(do=False)
    def test_get_zmq_connect_ipc(self):
        # mld_controller.get_zmq_connect(self, configfile)
        logger.debug("test_get_zmq_connect_ipc")
        """
        概要：zmqで接続文字列を取得する
        条件：設定ファイル=test_common/config.json
        結果：resultがipc設定用のzmq_pubとzmq_subであること
        """
        # 【前処理】
        config = read_json(TEST_COMMON_PATH + const.CONF_FILE)
        # 【実行】
        result = self.mld_proc.get_zmq_connect(config)

        # 【結果】
        logger.debug("test_get_zmq_connect_ipc [result] %s",
                     str(result))
        eq_(result, ["ipc:///tmp/feeds/ryu-mld",
                     "ipc:///tmp/feeds/mld-ryu"])

    @attr(do=False)
    def test_get_zmq_connect_tcp(self):
        logger.debug("test_get_zmq_connect_tcp")
        """
        概要：zmqで接続文字列を取得する
        条件：設定ファイル=test_common/config_tcp.json
        結果：resultがtcp設定用のmld_server_ipとofc_server_ipであること
        """
        # 【前処理】
        config = read_json(TEST_COMMON_PATH + "config_tcp.json")

        # 【実行】
        result = self.mld_proc.get_zmq_connect(config)

        # 【結果】
        logger.debug("test_get_zmq_connect_tcp [result] %s",
                     str(result))
        eq_(result, ["tcp://0.0.0.0:7002", "tcp://192.168.5.11:7002"])

    @attr(do=False)
    @raises(Exception)
    def test_get_zmq_connect_other(self):
        logger.debug("test_get_zmq_connect_other")
        """
        概要：zmqで接続文字列を取得する
        条件：設定ファイル=test_common/config_other.json
        結果：Exceptionが発生すること
        """
        # 【前処理】
        config = read_json(TEST_COMMON_PATH + "config_other.json")

        # 【実行】
        self.mld_proc.get_zmq_connect(config)

        # 【結果】
        logger.debug("test_get_zmq_connect_other [Exception] %s", e)

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
    def test_create_socket001(self):
        zmq_url = "ipc://"
        send_file_path = "/tmp/feeds/ut/mld-mld"
        recv_file_path = "/tmp/feeds/ut/ryu-mld"
        send_path = zmq_url + send_file_path
        recv_path = zmq_url + recv_file_path

        # CHECK TMP FILE(SEND)
        self.mld_proc.check_exists_tmp(send_file_path)
        # CHECK TMP FILE(RECV)
        self.mld_proc.check_exists_tmp(recv_file_path)

        self.mld_proc.create_socket(send_path, recv_path)

        ok_(self.mld_proc.send_sock)
        ok_(self.mld_proc.recv_sock)

        os.remove(send_file_path)
        os.remove(recv_file_path)
        os.rmdir("/tmp/feeds/ut/")

    @attr(do=False)
    def test_send_mldquey_regularly_gq(self):

        self.mld_proc.config[const.REGURALY_QUERY_TYPE] = "GQ"
        self.mld_proc.config[const.REGURALY_QUERY_INTERVAL] = 5
        self.mld_proc.config[const.MLD_ESW_IFNAME] = "eth0"

        # send_mldquery([mc_info])呼び出し確認
        mc_info = {const.MC_TAG_MC_ADDR: "::", const.MC_TAG_SERV_IP: None}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        send_thre = threading.Thread(
            target=self.mld_proc.send_mldquery_regularly)
        send_thre.start()
        # ループに入る分処理待ち
        time.sleep(2)
        # ループを抜ける
        self.mld_proc.SEND_LOOP = False
        send_thre.join()
        self.mld_proc.SEND_LOOP = True

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_send_mldquey_regularly_sq(self):
        self.mld_proc.config[const.REGURALY_QUERY_TYPE] = "SQ"
        self.mld_proc.config[const.REGURALY_QUERY_INTERVAL] = 6
        self.mld_proc.config[const.MC_QUERY_INTERVAL] = 1
        self.mld_proc.config[const.MLD_ESW_IFNAME] = "eth0"

        send_thre = threading.Thread(
            target=self.mld_proc.send_mldquery_regularly)
        send_thre.start()
        # ループに入る分処理待ち
        time.sleep(2)
        # ループを抜けさせる
        self.mld_proc.SEND_LOOP = False
        send_thre.join()
        self.mld_proc.SEND_LOOP = True

    @attr(do=False)
    def test_wait_query_interval(self):
        # Falseで指定した引数がTrueに更新されていること
        next_interval = Value(ctypes.c_bool, False)
        self.mld_proc.config[const.REGURALY_QUERY_INTERVAL] = 1
        self.mld_proc.wait_query_interval(
            next_interval,
            self.mld_proc.config[const.REGURALY_QUERY_INTERVAL])
        self.mld_proc.config[const.REGURALY_QUERY_INTERVAL] = \
            self.config[const.REGURALY_QUERY_INTERVAL]
        ok_(next_interval.value)

    @attr(do=False)
    def test_send_mldquery_no_next_interval(self):
        mc_info_list = [{const.MC_TAG_MC_ADDR: "ff38::1:1",
                         const.MC_TAG_SERV_IP: "2001:1::20"},
                        {const.MC_TAG_MC_ADDR: "ff38::1:2",
                         const.MC_TAG_SERV_IP: "2001:1::20"}]
        wait_time = 1
        qqrv = 2

        # 呼び出しメソッドのスタブ化
        self.mocker.StubOutWithMock(self.mld_proc, "create_mldquery")
        self.mocker.StubOutWithMock(self.mld_proc, "create_packet")
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_sw")
        for mc_info in mc_info_list:
            self.mld_proc.create_mldquery(
                mc_info[const.MC_TAG_MC_ADDR],
                mc_info[const.MC_TAG_SERV_IP]).AndReturn("mld")
            self.mld_proc.create_packet(
                self.config[const.C_TAG_ID], "mld").AndReturn("sendpkt")
            for i in range(qqrv):
                self.mld_proc.send_packet_to_sw(
                    "sendpkt", mc_info[const.MC_TAG_MC_ADDR],
                    self.mld_proc.config[const.C_TAG_ID])
        self.mocker.ReplayAll()

        self.mld_proc.send_mldquery(mc_info_list, wait_time)

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_send_mldquery_exists_next_interval(self):
        mc_info_list = [{const.MC_TAG_MC_ADDR: "ff38::1:1",
                         const.MC_TAG_SERV_IP: "2001:1::20"},
                        {const.MC_TAG_MC_ADDR: "ff38::1:2",
                         const.MC_TAG_SERV_IP: "2001:1::20"}]
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
        temp_qqic = self.mld_proc.QQIC
        self.mld_proc.QQIC = 125

        actual = self.mld_proc.create_mldquery(mc_addr, serv_ip)
        eq_(mc_addr, actual.address)
        eq_([], actual.srcs)
        eq_(self.mld_proc.QUERY_MAX_RESPONSE, actual.maxresp)
        eq_(self.mld_proc.QUERY_QRV, actual.qrv)
        eq_(self.mld_proc.QQIC, actual.qqic)

        self.mld_proc.QQIC = temp_qqic

    @attr(do=False)
    def test_create_mldquery_specific(self):
        # SpecificQueryを生成する
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
        temp_qqic = self.mld_proc.QQIC
        self.mld_proc.QQIC = 125

        actual = self.mld_proc.create_mldquery(mc_addr, serv_ip)
        eq_(mc_addr, actual.address)
        eq_([serv_ip], actual.srcs)
        eq_(self.mld_proc.QUERY_MAX_RESPONSE, actual.maxresp)
        eq_(self.mld_proc.QUERY_QRV, actual.qrv)
        eq_(self.mld_proc.QQIC, actual.qqic)

        self.mld_proc.QQIC = temp_qqic

    @attr(do=False)
    def test_create_mldreport(self):
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
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
        serv_ip = "2001:1::20"
        vid = self.config[const.C_TAG_ID]
        query = self.mld_proc.create_mldquery(mc_addr, serv_ip)
        actual = self.mld_proc.create_packet(vid, query)

        eth = actual.get_protocol(ethernet.ethernet)
        eq_(self.MAC, eth.src)
        eq_(self.mld_proc.QUERY_DST, eth.dst)

        vln = actual.get_protocol(vlan.vlan)
        eq_(vid, vln.vid)

        ip6 = actual.get_protocol(ipv6.ipv6)
        eq_(self.IP6, ip6.src)
        eq_(self.mld_proc.QUERY_DST_IP, ip6.dst)
        # 拡張ヘッダを持っていることを確認
        eq_(inet.IPPROTO_HOPOPTS, ip6.nxt)
        ok_(ip6.ext_hdrs)

        icmp6 = actual.get_protocol(icmpv6.icmpv6)
        eq_(icmpv6.MLD_LISTENER_QUERY, icmp6.type_)
        eq_(query, icmp6.data)

    @attr(do=False)
    def test_create_packet_query02(self):
        # MLD Queryを持つpacketを生成
        # icmpv6_extendにて拡張ヘッダーがない場合の動作確認
        # ip6のnexthederがinet.IPPROTO_ICMPV6となっていること
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
        vid = self.config[const.C_TAG_ID]
        query = self.mld_proc.create_mldquery(mc_addr, serv_ip)

        # VLAN
        vln = vlan.vlan(vid=vid, ethertype=ether.ETH_TYPE_IPV6)

        # MLDV2_Query
        # ETHER
        eth = ethernet.ethernet(
            ethertype=ether.ETH_TYPE_8021Q,
            src=self.MAC, dst=self.mld_proc.QUERY_DST)

        # IPV6 with ExtensionHeader
        ip6 = ipv6.ipv6(
            src=self.IP6, dst=self.mld_proc.QUERY_DST_IP,
            nxt=inet.IPPROTO_ICMPV6)

        # MLD Query
        icmp6 = icmpv6_extend(
            type_=icmpv6.MLD_LISTENER_QUERY, data=query)

        sendpkt = eth / vln / ip6 / icmp6
        sendpkt.serialize()

        ip6 = sendpkt.get_protocol(ipv6.ipv6)
        eq_(ip6.nxt, inet.IPPROTO_ICMPV6)

    @attr(do=False)
    @raises(Exception)
    def test_create_packet_query03(self):
        # MLD Queryを持つpacketを生成
        # icmpv6_extendにてquery.versionに6以外を設定した場合の動作確認
        # Exceptionが発生すること
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
        query = self.mld_proc.create_mldquery(mc_addr, serv_ip)

        query.version = 4

        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6, data=[
            ipv6.option(type_=5, len_=2, data="\x00\x00"),
            ipv6.option(type_=1, len_=0)])]

        # Exceptionが発生すること
        checksum_ip(query, len(ext_headers),
                    icmpv6.MLD_LISTENER_QUERY, inet.IPPROTO_ICMPV6)

    @attr(do=False)
    def test_create_packet_report(self):
        # MLD Reportを持つpacketを生成
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
        vid = self.config[const.C_TAG_ID]
        types = [icmpv6.ALLOW_NEW_SOURCES, icmpv6.CHANGE_TO_INCLUDE_MODE]
        report = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)
        actual = self.mld_proc.create_packet(vid, report)

        eth = actual.get_protocol(ethernet.ethernet)
        eq_(self.MAC, eth.src)
        eq_(self.mld_proc.REPORT_DST, eth.dst)

        vln = actual.get_protocol(vlan.vlan)
        eq_(vid, vln.vid)

        ip6 = actual.get_protocol(ipv6.ipv6)
        eq_(self.IP6, ip6.src)
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

        self.mld_proc.config[const.MLD_ESW_IFNAME] = "eth0"
        self.mld_proc.send_packet_to_sw(packet, "ff38::1:1", 200)

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
        dispatch_ = dispatch(const.CON_MAIN_DISPATCHER, 1)

        self.mocker.StubOutWithMock(self.mld_proc, "set_switch_config")
        self.mld_proc.set_switch_config(dispatch_.dispatch)
        self.mocker.ReplayAll()

        self.mld_proc.analyse_receive_packet(dispatch_)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_analyse_receive_packet_packetin_query(self):
        # packet-in受信時：queryであればreply_proxyを呼び出す
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
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
        serv_ip = "2001:1::20"
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
        dispatch_ = dispatch(const.CON_MAIN_DISPATCHER, 1)

        # set_switch_configがExceptionを返却
        self.mocker.StubOutWithMock(self.mld_proc, "set_switch_config")
        self.mld_proc.set_switch_config(
            {'data': None, 'type_': 11, 'datapathid': 1,
             'in_port': -1, 'cid': 0}).AndRaise(
                 Exception("test_analyse_receive_packet_exception"))

        # logger.errorの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "error")
        self.mld_proc.logger.error(IsA(str), None)
        self.mocker.ReplayAll()

        self.mld_proc.analyse_receive_packet(dispatch_)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_set_switch_config(self):

        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        dispatch_ = dispatch(const.CON_MAIN_DISPATCHER, datapathid)

        # flowmod_gen.initialize_flowsのスタブ化
        self.mocker.StubOutWithMock(
            self.mld_proc.flowmod_gen, "initialize_flows")
        self.mld_proc.flowmod_gen.initialize_flows(
            datapathid=datapathid,
            pbb_isid=self.mld_proc.switch_mld_info[
                const.SW_TAG_MLD_INFO_PBB_ISID],
            bvid=self.mld_proc.switch_mld_info[const.SW_TAG_MLD_INFO_BVID],
            ivid=self.mld_proc.switch_mld_info[const.SW_TAG_MLD_INFO_IVID]
            ).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        self.mocker.ReplayAll()

        self.mld_proc.set_switch_config(dispatch_)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_create_packetout(self):
        datapathid = self.mld_proc.edge_switch[const.SW_TAG_DATAPATHID]
        packet = ipv6.ipv6()

        actual = self.mld_proc.create_packetout(
            datapathid, self.mld_proc.edge_switch[
                const.SW_TAG_EDGE_ROUTER_PORT], packet)

        ok_(type(actual) is packet_out_data)
        eq_(datapathid, actual.datapathid)
        eq_(ofproto_v1_3.OFPP_CONTROLLER, actual.in_port)
        eq_(ofproto_v1_3.OFP_NO_BUFFER, actual.buffer_id)
        eq_(1, len(actual.actions))
        eq_(self.mld_proc.edge_switch[const.SW_TAG_EDGE_ROUTER_PORT],
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
        serv_ip = "2001:1::20"
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        port_no = 1
        cid = 2101
        self.mld_proc.config[const.USER_TIME_OUT] = 300

        self.mld_proc.ch_info.update_ch_info(
            mc_addr, serv_ip, datapathid, port_no, cid)
        before_size = len(self.mld_proc.ch_info.user_info_list)

        self.mld_proc.check_user_timeout()
        after_size = len(self.mld_proc.ch_info.user_info_list)

        eq_(before_size, after_size)

        # 元の値に戻す
        self.mld_proc.config[const.USER_TIME_OUT] = \
            self.config[const.USER_TIME_OUT]

    @attr(do=False)
    def test_check_user_timeout_timeout(self):
        # タイムアウトのユーザーあり

        # 2秒でタイムアウトとする
        self.mld_proc.config[const.USER_TIME_OUT] = 2

        mc_addr1 = "ff38::1:1"
        serv_ip = "2001:1::20"
        datapathid2 = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
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
        datapathid3 = self.mld_proc.switches[2][const.SW_TAG_DATAPATHID]

        port_no3 = 3
        cid4 = 13301
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid3, port_no3, cid4)

        mc_addr2 = "ff38::1:2"
        cid5 = 22102
        self.mld_proc.ch_info.update_ch_info(
            mc_addr2, serv_ip, datapathid2, port_no1, cid5)

        # reply_to_ryuの呼び出し確認
        #   cid1が削除された段階でreply_typeがポート駆除で呼び出されること
        self.mocker.StubOutWithMock(self.mld_proc, "reply_to_ryu")
        self.mld_proc.reply_to_ryu(
            mc_addr1, serv_ip, datapathid2, port_no1,
            const.CON_REPLY_DEL_PORT)
        self.mocker.ReplayAll()

        # check_user_timeout実行前の件数確認
        eq_(5, len(self.mld_proc.ch_info.user_info_list))

        self.mld_proc.check_user_timeout()

        # sleep前の2件がタイムアウト
        eq_(3, len(self.mld_proc.ch_info.user_info_list))

        # 残った３件の内容確認
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
    def test_check_user_timeout_exception(self):
        # 1秒でタイムアウトとする
        self.mld_proc.config[const.USER_TIME_OUT] = 1

        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        port_no = 1
        cid = 12101
        self.mld_proc.ch_info.update_ch_info(
            mc_addr, serv_ip, datapathid, port_no, cid)

        # タイムアウトを起こすために処理待ち
        time.sleep(1)

        # remove_ch_infoで例外を返却
        self.mocker.StubOutWithMock(self.mld_proc.ch_info, "remove_ch_info")
        self.mld_proc.ch_info.remove_ch_info(
            mc_addr, serv_ip, datapathid, port_no, cid).AndRaise(
                Exception("test_check_user_timeout_exception"))

        # errorの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "error")
        self.mld_proc.logger.error(IsA(str), None)
        self.mocker.ReplayAll()

        self.mld_proc.check_user_timeout()
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_reply_proxy_no_user(self):
        # 視聴情報がない場合は何もしない
        actual = self.mld_proc.reply_proxy("::", [])
        eq_(-1, actual)

    @attr(do=False)
    def test_reply_proxy_exists_user_gq(self):
        # 視聴情報がありGeneralQueryの場合、視聴中のmcアドレス分p-out
        mc_addr1 = "ff38::1:1"
        serv_ip = "2001:1::20"
        datapathid2 = 2
        port_no1 = 1
        cid1 = 12101
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no1, cid1)
        cid2 = 12102
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no1, cid2)

        mc_addr2 = "ff38::1:2"
        serv_ip = "2001:1::20"
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
        serv_ip = "2001:1::20"
        datapathid2 = 2
        port_no1 = 1
        cid1 = 12101
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no1, cid1)
        cid2 = 12102
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no1, cid2)

        mc_addr2 = "ff38::1:2"
        serv_ip = "2001:1::20"
        cid3 = 22101
        self.mld_proc.ch_info.update_ch_info(
            mc_addr2, serv_ip, datapathid2, port_no1, cid3)

        # 受信したmc_addrを引数にcreate_mldreportが呼び出されることを確認
        report_type = [icmpv6.MODE_IS_INCLUDE]
        self.mocker.StubOutWithMock(self.mld_proc, "create_mldreport")
        self.mld_proc.create_mldreport(
            mc_address=mc_addr1, mc_serv_ip=serv_ip, report_types=report_type)

        self.mocker.StubOutWithMock(self.mld_proc, "create_packet")
        self.mld_proc.create_packet(IsA(int), None)

        self.mocker.StubOutWithMock(self.mld_proc, "create_packetout")
        self.mld_proc.create_packetout(
            datapathid=self.mld_proc.edge_switch[const.SW_TAG_DATAPATHID],
            port=self.mld_proc.edge_switch[const.SW_TAG_EDGE_ROUTER_PORT],
            packet=None)

        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))
        self.mocker.ReplayAll()

        self.mld_proc.reply_proxy(mc_addr1, [serv_ip])
        self.mocker.VerifyAll()

    @attr(do=False)
    @raises(ExpectedMethodCallsError)
    def test_reply_proxy_exists_user_sq_no_user(self):
        # 視聴情報がありSpecificQuery場合、受信したmcアドレスが視聴中ででなければなにもしない
        mc_addr1 = "ff38::1:1"
        serv_ip = "2001:1::20"
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
    def test_reply_proxy_exists_user_sq_no_srcs(self):
        # 視聴情報がありSpecificQuery場合、受信したmcアドレスが視聴中ででなければなにもしない
        mc_addr1 = "ff38::1:1"
        serv_ip = "2001:1::20"
        datapathid2 = 2
        port_no1 = 1
        cid1 = 12101
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no1, cid1)
        cid2 = 12102
        self.mld_proc.ch_info.update_ch_info(
            mc_addr1, serv_ip, datapathid2, port_no1, cid2)

        # logger.infoが呼び出さることを確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "info")
        self.mld_proc.logger.info("this query has no Source Address.")
        self.mocker.ReplayAll()

        self.mld_proc.reply_proxy(mc_addr1, [])
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_manage_user_reply(self):
        # update_user_infoがCON_REPLY_NOTHING以外を返却する場合はreply_to_ryuを呼び出す
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
        types = [icmpv6.MODE_IS_INCLUDE]
        mld = self.mld_proc.create_mldreport(mc_addr, serv_ip, types)
        data = icmpv6.icmpv6(
            type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
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
    def test_update_user_info_no_mcinfo(self):
        # multicast_info.jsonに存在しないアドレスのペアを受信した場合
        mc_addr = "ff38::1:1"
        serv_ip = "2001::1:30"
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        cid = 100

        # logger.infoの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "info")
        self.mld_proc.logger.info(
            "this multicast address[%s] and server ip[%s] %s",
            mc_addr, serv_ip, "is not exist multicast_info.json.")
        self.mocker.ReplayAll()

        actual = self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid,
            icmpv6.ALLOW_NEW_SOURCES)
        eq_(const.CON_REPLY_NOTHING, actual)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_update_user_info_allow(self):
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
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
        serv_ip = "2001:1::20"
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        cid = 100

        # remove_ch_infoの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.ch_info, "remove_ch_info")
        self.mld_proc.ch_info.remove_ch_info(
            mc_addr=mc_addr, serv_ip=serv_ip, datapathid=datapathid,
            port_no=in_port, cid=cid).AndReturn(const.CON_REPLY_NOTHING)

        # send_mldqueryの呼び出し確認
        mc_info = {const.MC_TAG_MC_ADDR: mc_addr,
                   const.MC_TAG_SERV_IP: serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        actual = self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid,
            icmpv6.BLOCK_OLD_SOURCES)

        # sendの実行待ち
        time.sleep(1)

        eq_(const.CON_REPLY_NOTHING, actual)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_update_user_info_include(self):
        # 既存ユーザのMODE_IS_INCLUDEの場合
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
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
    def test_update_user_info_exclude(self):
        # CHANGE_TO_EXCLUDE_MODEの場合
        mc_addr = "ff38::1:1"
        serv_ip = ""
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        cid = 100

        # logger.infoの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "info")
        self.mld_proc.logger.info("input server_ip when VLC started.")
        self.mocker.ReplayAll()

        actual = self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid,
            icmpv6.CHANGE_TO_EXCLUDE_MODE)
        eq_(const.CON_REPLY_NOTHING, actual)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_update_user_info_other(self):
        # 上記以外のtypeはCON_REPLY_NOTHINGを返却
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        cid = 100

        types = [icmpv6.CHANGE_TO_INCLUDE_MODE,
                 icmpv6.MODE_IS_EXCLUDE]

        for type_ in types:
            actual = self.mld_proc.update_user_info(
                mc_addr, serv_ip, datapathid, in_port, cid, type_)
            eq_(const.CON_REPLY_NOTHING, actual)

    @attr(do=False)
    def test_update_user_info_exception(self):
        # 上記以外のtypeはCON_REPLY_NOTHINGを返却
        mc_addr = "ff38::1:1"
        serv_ip = "2001:1::20"
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        cid = 100

        # update_ch_infoで例外を返却
        self.mocker.StubOutWithMock(self.mld_proc.ch_info, "update_ch_info")
        self.mld_proc.ch_info.update_ch_info(
            mc_addr=mc_addr, serv_ip=serv_ip, datapathid=datapathid,
            port_no=in_port, cid=cid).AndRaise(
                Exception("test_update_user_info_exception"))

        # errorの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc.logger, "error")
        self.mld_proc.logger.error(IsA(str), None)
        self.mocker.ReplayAll()

        actual = self.mld_proc.update_user_info(
            mc_addr, serv_ip, datapathid, in_port, cid,
            icmpv6.ALLOW_NEW_SOURCES)
        eq_(const.CON_REPLY_NOTHING, actual)
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_reply_to_ryu_add_mc_be(self):
        # reply_typeがCON_REPLY_ADD_MC_GROUPの場合
        mc_addr = str(self.mc_info_list[0][const.MC_TAG_MC_ADDR])
        serv_ip = str(self.mc_info_list[0][const.MC_TAG_SERV_IP])
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        cid = 100
        reply_type = const.CON_REPLY_ADD_MC_GROUP

        # ベストエフォートサービス
        self.mld_proc.mc_info_list[0][const.MC_TAG_MC_TYPE] = \
            self.mld_proc.BEST_EFFORT
        self.mld_proc.ch_info.update_ch_info(
            mc_addr, serv_ip, datapathid, in_port, cid)

        # flowmod_gen.start_mgをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "start_mg")
        self.mld_proc.flowmod_gen.start_mg(
            multicast_address=mc_addr, datapathid=datapathid, portno=in_port,
            mc_ivid=self.mld_proc.switch_mc_info[const.SW_TAG_MLD_INFO_IVID],
            ivid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_IVID],
            pbb_isid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_PBB_ISID],
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

        self.mld_proc.mc_info_list[0][const.MC_TAG_MC_TYPE] = \
            self.mc_info_list[0][const.MC_TAG_MC_TYPE]

    @attr(do=False)
    @raises(ExpectedMethodCallsError)
    def test_reply_to_ryu_add_mc_qa(self):
        # reply_typeがCON_REPLY_ADD_MC_GROUPの場合
        mc_addr = str(self.mc_info_list[0][const.MC_TAG_MC_ADDR])
        serv_ip = str(self.mc_info_list[0][const.MC_TAG_SERV_IP])
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        cid = 100
        reply_type = const.CON_REPLY_ADD_MC_GROUP

        # 品質保証サービス
        self.mld_proc.mc_info_list[0][const.MC_TAG_MC_TYPE] = \
            self.mld_proc.QUALITY_ASSURANCE
        self.mld_proc.ch_info.update_ch_info(
            mc_addr, serv_ip, datapathid, in_port, cid)

        # flowmod_gen.start_mgをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "start_mg")
        self.mld_proc.flowmod_gen.start_mg(
            multicast_address=mc_addr, datapathid=datapathid, portno=in_port,
            mc_ivid=self.mld_proc.switch_mc_info[const.SW_TAG_MLD_INFO_IVID],
            ivid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_IVID],
            pbb_isid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_PBB_ISID],
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

        self.mld_proc.mc_info_list[0][const.MC_TAG_MC_TYPE] = \
            self.mc_info_list[0][const.MC_TAG_MC_TYPE]

    @attr(do=False)
    def test_reply_to_ryu_add_sw(self):
        # reply_typeがCON_REPLY_ADD_SWITCHの場合
        mc_addr = str(self.mc_info_list[0][const.MC_TAG_MC_ADDR])
        serv_ip = str(self.mc_info_list[0][const.MC_TAG_SERV_IP])
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        reply_type = const.CON_REPLY_ADD_SWITCH

        # flowmod_gen.add_datapathをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "add_datapath")
        self.mld_proc.flowmod_gen.add_datapath(
            multicast_address=mc_addr, datapathid=datapathid, portno=in_port,
            ivid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_IVID],
            pbb_isid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_PBB_ISID],
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
        mc_addr = str(self.mc_info_list[0][const.MC_TAG_MC_ADDR])
        serv_ip = str(self.mc_info_list[0][const.MC_TAG_SERV_IP])
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        reply_type = const.CON_REPLY_ADD_PORT

        # flowmod_gen.add_portをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "add_port")
        self.mld_proc.flowmod_gen.add_port(
            multicast_address=mc_addr, datapathid=datapathid, portno=in_port,
            ivid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_IVID],
            pbb_isid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_PBB_ISID],
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
        mc_addr = str(self.mc_info_list[0][const.MC_TAG_MC_ADDR])
        serv_ip = str(self.mc_info_list[0][const.MC_TAG_SERV_IP])
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        cid = 100
        reply_type = const.CON_REPLY_DEL_MC_GROUP

        # ベストエフォートサービス
        self.mld_proc.mc_info_list[0][const.MC_TAG_MC_TYPE] = \
            self.mld_proc.BEST_EFFORT
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
            multicast_address=mc_addr, datapathid=datapathid, portno=in_port,
            mc_ivid=self.mld_proc.switch_mc_info[const.SW_TAG_MLD_INFO_IVID],
            ivid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_IVID],
            pbb_isid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_PBB_ISID],
            bvid=4001).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        self.mocker.ReplayAll()

        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port, reply_type)
        self.mocker.VerifyAll()

        self.mld_proc.mc_info_list[0][const.MC_TAG_MC_TYPE] = \
            self.mc_info_list[0][const.MC_TAG_MC_TYPE]

    @attr(do=False)
    @raises(ExpectedMethodCallsError)
    def test_reply_to_ryu_del_mc_qa(self):
        mc_addr = str(self.mc_info_list[0][const.MC_TAG_MC_ADDR])
        serv_ip = str(self.mc_info_list[0][const.MC_TAG_SERV_IP])
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        cid = 100
        reply_type = const.CON_REPLY_DEL_MC_GROUP

        # 品質保証サービス
        self.mld_proc.mc_info_list[0][const.MC_TAG_MC_TYPE] = \
            self.mld_proc.QUALITY_ASSURANCE
        self.mld_proc.ch_info.update_ch_info(
            mc_addr, serv_ip, datapathid, in_port, cid)

        # create_mldreportが呼び出されないことの確認
        self.mocker.StubOutWithMock(self.mld_proc, "create_mldreport")
        self.mld_proc.create_mldreport(IsA(str), IsA(str), IsA(list))

        # flowmod_gen.remove_mgをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "remove_mg")
        self.mld_proc.flowmod_gen.remove_mg(
            multicast_address=mc_addr, datapathid=datapathid, portno=in_port,
            mc_ivid=self.mld_proc.switch_mc_info[const.SW_TAG_MLD_INFO_IVID],
            ivid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_IVID],
            pbb_isid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_PBB_ISID],
            bvid=4001).AndReturn(0)

        # send_packet_to_ryuの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_packet_to_ryu")
        self.mld_proc.send_packet_to_ryu(IsA(dispatch))

        self.mocker.ReplayAll()

        self.mld_proc.reply_to_ryu(
            mc_addr, serv_ip, datapathid, in_port, reply_type)
        self.mocker.VerifyAll()

        self.mld_proc.mc_info_list[0][const.MC_TAG_MC_TYPE] = \
            self.mc_info_list[0][const.MC_TAG_MC_TYPE]

    @attr(do=False)
    def test_reply_to_ryu_del_sw(self):
        # reply_typeがCON_REPLY_DEL_SWITCHの場合
        mc_addr = str(self.mc_info_list[0][const.MC_TAG_MC_ADDR])
        serv_ip = str(self.mc_info_list[0][const.MC_TAG_SERV_IP])
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        reply_type = const.CON_REPLY_DEL_SWITCH

        # flowmod_gen.remove_datapathをスタブ化
        self.mocker.StubOutWithMock(
            self.mld_proc.flowmod_gen, "remove_datapath")
        self.mld_proc.flowmod_gen.remove_datapath(
            multicast_address=mc_addr, datapathid=datapathid, portno=in_port,
            ivid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_IVID],
            pbb_isid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_PBB_ISID],
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
        mc_addr = str(self.mc_info_list[0][const.MC_TAG_MC_ADDR])
        serv_ip = str(self.mc_info_list[0][const.MC_TAG_SERV_IP])
        datapathid = self.mld_proc.switches[1][const.SW_TAG_DATAPATHID]
        in_port = 1
        reply_type = const.CON_REPLY_DEL_PORT

        # flowmod_gen.remove_portをスタブ化
        self.mocker.StubOutWithMock(self.mld_proc.flowmod_gen, "remove_port")
        self.mld_proc.flowmod_gen.remove_port(
            multicast_address=mc_addr, datapathid=datapathid, portno=in_port,
            ivid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_IVID],
            pbb_isid=self.mc_info_list[0][const.SW_TAG_MLD_INFO_PBB_ISID],
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
        recv_thre = threading.Thread(target=self.mld_proc.receive_from_ryu)
        recv_thre.daemon = True
        recv_thre.start()
        time.sleep(1)
        self.mld_proc.RECV_LOOP = False
        time.sleep(1)
        self.mld_proc.RECV_LOOP = True

    @attr(do=False)
    def test_end_process(self):
        # 送受信のループフラグがFalseになっていること
        # SYstemExitが発生すること
        try:
            self.mld_proc.end_process()
        except SystemExit:
            eq_(self.mld_proc.SEND_LOOP, False)
            eq_(self.mld_proc.RECV_LOOP, False)


class test_user_manage():

    mc_addr1 = "ff38::1:1"
    mc_addr2 = "ff38::1:2"
    serv_ip = "2001:1::20"
    datapathid1 = 276595101184
    datapathid2 = 276596903168
    in_port1 = 1
    in_port2 = 2

    # このクラスのテストケースを実行する前に１度だけ実行する
    @classmethod
    def setup_class(cls):
        logger.debug("setup_class")
        config = read_json(TEST_COMMON_PATH + const.CONF_FILE)
        cls.config = config.data[const.SETTING]

        # テスト用の設定ファイルを読み込ませる
        mld_process.COMMON_PATH = TEST_COMMON_PATH
        cls.mld_proc = mld_process.mld_process()

    # このクラスのテストケースをすべて実行した後に１度だけ実行する
    @classmethod
    def teardown_class(cls):
        logger.debug("teardown")

    def setup(self):
        self.mocker = Mox()

    def teardown(self):
        self.mocker.UnsetStubs()
        # 設定値の初期化
        self.mld_proc.ch_info = channel_info(self.config)
        self.mld_proc.config = self.config

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
        # 既存ユーザに対するMODE_IS_INCLUDE
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
    def test_update_user_03(self):
        # 視聴継続（既存ユーザに対するINCLUDE複数件）
        #   既存のユーザ情報が2件更新されていること

        # 事前準備
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1, 1111)
        eq_(2, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1111, self.mld_proc.ch_info.user_info_list[1].cid)

        cid = 1111
        # 更新前timeの取り出し
        bf_time1 = self.mld_proc.ch_info.user_info_list[0].time
        bf_time2 = self.mld_proc.ch_info.user_info_list[1].time

        types = [icmpv6.MODE_IS_INCLUDE, icmpv6.MODE_IS_INCLUDE]
        mld = self.mld_proc.create_mldreport(
            self.mc_addr2, self.serv_ip, types)

        record_list = []
        record_list.append(
            icmpv6.mldv2_report_group(
                type_=icmpv6.MODE_IS_INCLUDE, address=self.mc_addr1,
                srcs=[self.serv_ip]))
        record_list.append(
            icmpv6.mldv2_report_group(
                type_=icmpv6.MODE_IS_INCLUDE, address=self.mc_addr2,
                srcs=[self.serv_ip]))
        mld = icmpv6.mldv2_report(records=record_list)

        data = icmpv6.icmpv6(
            type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)
        dispatch_ = dispatch(
            const.CON_PACKET_IN, self.datapathid1, self.in_port1, cid, data)

        # 既存ユーザに対するMODE_IS_INCLUDE
        self.mld_proc.manage_user(dispatch_)

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(2, len(self.mld_proc.ch_info.channel_info.keys()))
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr1, self.serv_ip]
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        user_info = ch_sw_info.port_info[self.in_port1]
        ch_user_info1 = user_info[cid]

        # channel_user_info(cid)
        regist_time1 = ch_user_info1.time
        ok_(bf_time1 < regist_time1)

        # channel_info(mc_addr, serv_ip, datapathid)
        sw_info = self.mld_proc.ch_info.channel_info[
            self.mc_addr2, self.serv_ip]
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no)
        user_info = ch_sw_info.port_info[self.in_port1]
        ch_user_info2 = user_info[cid]

        # channel_user_info(cid)
        regist_time2 = ch_user_info2.time
        # timeが更新されていること
        ok_(bf_time2 < regist_time2)

        # user_info_list
        #   更新されたユーザがリストの末尾に移動していること
        eq_(2, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)
        eq_(1111, self.mld_proc.ch_info.user_info_list[1].cid)

        ch_user_info1 = self.mld_proc.ch_info.user_info_list[0]
        eq_(cid, ch_user_info1.cid)
        eq_(regist_time1, ch_user_info1.time)

        ch_user_info2 = self.mld_proc.ch_info.user_info_list[1]
        eq_(cid, ch_user_info2.cid)
        eq_(regist_time2, ch_user_info2.time)

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
        mc_info = {const.MC_TAG_MC_ADDR: self.mc_addr1,
                   const.MC_TAG_SERV_IP: self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        cid = 1112
        # ユーザの削除
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.BLOCK_OLD_SOURCES)

        # sendの実行待ち
        time.sleep(1)

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
        mc_info = {const.MC_TAG_MC_ADDR: self.mc_addr1,
                   const.MC_TAG_SERV_IP: self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        cid = 1111
        # ユーザの削除(ポート削除)
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1,
            cid, icmpv6.BLOCK_OLD_SOURCES)

        # sendの実行待ち
        time.sleep(1)

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
        mc_info = {const.MC_TAG_MC_ADDR: self.mc_addr1,
                   const.MC_TAG_SERV_IP: self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        cid = 1211
        # ユーザの削除(SW削除)
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid2, self.in_port1,
            cid, icmpv6.BLOCK_OLD_SOURCES)

        # sendの実行待ち
        time.sleep(1)

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
        mc_info = {const.MC_TAG_MC_ADDR: self.mc_addr1,
                   const.MC_TAG_SERV_IP: self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        cid = 1121
        # ユーザの削除(MC削除)
        actual = self.mld_proc.update_user_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port2,
            cid, icmpv6.BLOCK_OLD_SOURCES)

        # sendの実行待ち
        time.sleep(1)

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

        # sendの実行待ち
        time.sleep(1)

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
        mc_info = {const.MC_TAG_MC_ADDR: self.mc_addr2,
                   const.MC_TAG_SERV_IP: self.serv_ip}
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        self.mld_proc.send_mldquery([mc_info])
        self.mld_proc.send_mldquery([mc_info])
        self.mocker.ReplayAll()

        cid1 = 1112
        # ユーザの削除
        actual = self.mld_proc.update_user_info(
            self.mc_addr2, self.serv_ip, self.datapathid1, self.in_port1,
            cid1, icmpv6.BLOCK_OLD_SOURCES)

        # sendの実行待ち
        time.sleep(2)

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
        self.mld_proc.config[const.USER_TIME_OUT] = 3

        self.mld_proc.ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, 1111)

        eq_(1, len(self.mld_proc.ch_info.user_info_list))
        eq_(1111, self.mld_proc.ch_info.user_info_list[0].cid)

        # reply_proxyの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "reply_proxy")
        self.mld_proc.reply_proxy(self.mc_addr1, [self.serv_ip])

        # send_mldqueryの呼び出し確認
        self.mocker.StubOutWithMock(self.mld_proc, "send_mldquery")
        mc_info = {const.MC_TAG_MC_ADDR: self.mc_addr1,
                   const.MC_TAG_SERV_IP: self.serv_ip}
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
        time.sleep(3)

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
        temp_timeout = self.mld_proc.config[const.USER_TIME_OUT]
        self.mld_proc.config[const.USER_TIME_OUT] = 3

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
        time.sleep(3)
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
        mc_info = {const.MC_TAG_MC_ADDR: self.mc_addr1,
                   const.MC_TAG_SERV_IP: self.serv_ip}
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

        self.mld_proc.config[const.USER_TIME_OUT] = temp_timeout

    @attr(do=False)
    def test_channel_info_init_no_config(self):
        # config.db_connect_strが指定されなかった場合
        ch_info = channel_info(config={const.DB_CONNECT_STR: ""})
        eq_(ch_info.accessor.client, None)

        # 事前状態確認
        eq_({}, ch_info.channel_info)
        eq_([], ch_info.user_info_list)

        cid = 1111
        ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, cid)

        # 登録はできていることを確認

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(1, len(ch_info.channel_info.keys()))
        eq_((self.mc_addr1, self.serv_ip), ch_info.channel_info.keys()[0])
        sw_info = ch_info.channel_info[self.mc_addr1, self.serv_ip]
        eq_(1, len(sw_info.keys()))
        eq_(self.datapathid1, sw_info.keys()[0])
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no, cid)
        eq_(1, len(ch_sw_info.port_info.keys()))
        eq_(self.in_port1, ch_sw_info.port_info.keys()[0])
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(1, len(user_info.keys()))
        eq_(cid, user_info.keys()[0])

    @attr(do=False)
    def test_channel_info_init_exception(self):
        # config.db_connect_strが不正な場合（DB接続に失敗）

        # error呼び出し確認
        self.mocker.StubOutWithMock(user_manage.logger, "error")
        user_manage.logger.error("%s", None)
        self.mocker.ReplayAll()

        channel_info({const.DB_CONNECT_STR: "not ip address"})
        self.mocker.VerifyAll()

    @attr(do=False)
    def test_update_user_info_exception(self):
        # accessor.upsert(VIEWR_DATA, self) で例外が発生
        ch_info = channel_info(self.config)

        # accessor.upsert(VIEWR_DATA, self)でExceptionを『返却
        self.mocker.StubOutWithMock(ch_info.accessor, "upsert")
        ch_info.accessor.upsert("viewerdata", ch_info).AndRaise(
            Exception("test_update_user_info_exception"))

        # error呼び出し確認
        self.mocker.StubOutWithMock(user_manage.logger, "error")
        user_manage.logger.error("%s ", None)
        self.mocker.ReplayAll()

        # 事前状態確認
        eq_({}, ch_info.channel_info)
        eq_([], ch_info.user_info_list)

        cid = 1111
        ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, cid)

        # 登録はできていることを確認

        # channel_info(mc_addr, serv_ip, datapathid)
        eq_(1, len(ch_info.channel_info.keys()))
        eq_((self.mc_addr1, self.serv_ip), ch_info.channel_info.keys()[0])
        sw_info = ch_info.channel_info[self.mc_addr1, self.serv_ip]
        eq_(1, len(sw_info.keys()))
        eq_(self.datapathid1, sw_info.keys()[0])
        ch_sw_info = sw_info[self.datapathid1]

        # channel_switch_info(port_no, cid)
        eq_(1, len(ch_sw_info.port_info.keys()))
        eq_(self.in_port1, ch_sw_info.port_info.keys()[0])
        user_info = ch_sw_info.port_info[self.in_port1]
        eq_(1, len(user_info.keys()))
        eq_(cid, user_info.keys()[0])

        self.mocker.VerifyAll()

    @attr(do=False)
    def test_remove_user_info_exception(self):
        # accessor.upsert(VIEWR_DATA, self) で例外が発生
        ch_info = channel_info(self.config)

        # ユーザ登録
        cid = 1111
        ch_info.update_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, cid)
        eq_(1, len(ch_info.user_info_list))
        eq_(cid, ch_info.user_info_list[0].cid)

        # accessor.upsert(VIEWR_DATA, self)でExceptionを『返却
        self.mocker.StubOutWithMock(ch_info.accessor, "upsert")
        ch_info.accessor.upsert("viewerdata", ch_info).AndRaise(
            Exception("test_remove_user_info_exception"))

        # error呼び出し確認
        self.mocker.StubOutWithMock(user_manage.logger, "error")
        user_manage.logger.error("%s ", None)
        self.mocker.ReplayAll()

        cid = 1111
        ch_info.remove_ch_info(
            self.mc_addr1, self.serv_ip, self.datapathid1, self.in_port1, cid)

        # 削除はできていることを確認

        # channel_info(mc_addr, serv_ip, datapathid)
        #   視聴情報が存在しないこと
        eq_({}, self.mld_proc.ch_info.channel_info)

        # user_info_list
        #   ユーザが削除されていること
        eq_([], self.mld_proc.ch_info.user_info_list)

        self.mocker.VerifyAll()


class dummy_socket():
    def recv(self):
        logger.debug("dummy recv...")
        time.sleep(1)
        dummydata = dispatch(type_=0, datapathid=0, data="dummy")
        return cPickle.dumps(dummydata)

    def poll(self, arg):
        return 1


if __name__ == '__main__':
    unittest.main()