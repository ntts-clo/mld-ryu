# coding: utf-8
# zmq install
#  >sudo apt-get install libzmq-dev
#  >sudo apt-get install python-zmq

from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from scapy import sendrecv
from scapy import packet as scapy_packet
from scapy.layers import inet6  # sendpの警告回避
from multiprocessing import Process, Value
import os
import traceback
import json
import logging
import cPickle
import zmq
import sys
import time
import ctypes
import threading
import re
import subprocess

from user_manage import channel_info, channel_user_info
from flowmod_gen import flow_mod_generator

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
COMMON_PATH = DIR_PATH + "/../../common/"
sys.path.append(COMMON_PATH)
from icmpv6_extend import icmpv6_extend
from zmq_dispatch import dispatch, packet_out_data
from read_json import read_json
import mld_const as const


# ======================================================================
# mld_process
# ======================================================================
class mld_process():

    # 定期クエリのタイプ
    GENERAL_QUERY = "GQ"
    SPECIFIC_QUERY = "SQ"

    # 対象マルチキャストのサービスのタイプ
    BEST_EFFORT = "BE"
    QUALITY_ASSURANCE = "QA"

    # Queryの設定値
    QUERY_MAX_RESPONSE = 10000
    QUERY_QRV = 2

    # etherのdst(macアドレス)の設定値
    QUERY_DST = "33:33:00:00:00:01"
    REPORT_DST = "33:33:00:00:00:16"

    # ipv6のdstipの設定値
    QUERY_DST_IP = "ff02::1"
    REPORT_DST_IP = "ff02::16"

    # ネットワークインターフェースの情報のKEY
    IF_KEY_MAC = "mac"
    IF_KEY_IP6 = "ip6"

    # 送受信のループフラグ
    SEND_LOOP = True
    RECV_LOOP = True

    # ZMQ受信間隔
    ZMQ_POLL_INTERVAL = 10

    def __init__(self):
        try:
            # ロガーの設定
            self.logger = logging.getLogger(__name__)
            self.logger.debug("")

            # 設定情報読み込み
            config = read_json(COMMON_PATH + const.CONF_FILE)
            self.logger.info("%s:%s", const.CONF_FILE, json.dumps(
                config.data, indent=4, sort_keys=True, ensure_ascii=False))
            self.config = config.data[const.SETTING]

            # IF情報取得
            self.ifinfo = {}
            self.ifinfo = self.get_interface_info(
                self.config[const.MLD_ESW_IFNAME])

            # QueryのQQIC設定
            self.QQIC = self.calculate_qqic(
                self.config[const.REGURALY_QUERY_INTERVAL])

            # 視聴情報初期化
            self.ch_info = channel_info(self.config)

            # スイッチ情報読み込み
            switches = read_json(COMMON_PATH + const.SWITCH_INFO)
            self.logger.info("%s:%s", const.SWITCH_INFO, json.dumps(
                switches.data, indent=4, sort_keys=True, ensure_ascii=False))
            self.switch_mld_info = switches.data[const.SW_TAG_MLD_INFO]
            self.switch_mc_info = switches.data[const.SW_TAG_MC_INFO]
            self.switches = switches.data[const.SW_TAG_SWITCHES]
            for switch in self.switches:
                if switch[const.SW_TAG_NAME] == const.SW_NAME_ESW:
                    self.edge_switch = switch
                    break

            # マルチキャスト情報読み込み
            mc_info = read_json(COMMON_PATH + const.MULTICAST_INFO)
            self.logger.info("%s:%s", const.MULTICAST_INFO, json.dumps(
                mc_info.data, indent=4, sort_keys=True, ensure_ascii=False))
            self.mc_info_list = mc_info.data[const.MC_TAG_MC_INFO]
            self.mc_info_dict = {}
            for mc_info in self.mc_info_list:
                self.mc_info_dict[
                    mc_info[const.MC_TAG_MC_ADDR],
                    mc_info[const.MC_TAG_SERV_IP]] = mc_info

            # bvidパターン読み込み
            bvid_variation = read_json(COMMON_PATH + const.BVID_VARIATION)
            self.logger.info("%s:%s", const.BVID_VARIATION, json.dumps(
                bvid_variation.data, indent=4, sort_keys=True,
                ensure_ascii=False))
            bvid_variations = bvid_variation.data[const.BV_TAG_BV_INFO]
            self.bvid_variation = {}
            for bvid_variation in bvid_variations:
                self.bvid_variation[bvid_variation[const.BV_TAG_KEY]] = \
                    bvid_variation[const.BV_TAG_BVID]

            # ZMQの接続文字列を取得
            zmq_conn = self.get_zmq_connect(config)
            self.zmq_pub = zmq_conn[0]
            self.zmq_sub = zmq_conn[1]

            # ZMQ送受信用ソケット生成
            self.create_socket(self.zmq_pub, self.zmq_sub)
            # Flowmod生成用インスタンス
            self.flowmod_gen = flow_mod_generator(self.switches)

        except:
            self.logger.error("%s ", traceback.print_exc())
            raise KeyboardInterrupt

    # =========================================================================
    # get_interface_info
    # =========================================================================
    def get_interface_info(self, iface):
        self.logger.debug("")
        self.logger.debug("iface : %s", iface)

        # MACアドレスの正規表現
        MAC_PATTERN = "([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}"
        mac_pat = re.compile(MAC_PATTERN)
        # IPv6リンクローカルアドレスの正規表現
        IP6_PATTERN = "fe80:[0-9a-fA-F:]*/[0-9]{2}"
        ip6_pat = re.compile(IP6_PATTERN)

        ifconf = ""
        ifname = ""
        ifdict = {}

        try:
            # ifconfigの結果を取得する
            ifconf = subprocess.check_output(["ifconfig", iface])
        except subprocess.CalledProcessError:
            # ifconfigの実行でエラーが発生した場合
            self.logger.error(
                "input exist network interface name where " +
                const.CONF_FILE + " at 'mld_esw_ifname'.")
            self.end_process()

        for line in ifconf.split("\n"):
            if not len(line) == 0:
                if not line[0] == " ":
                    # インターフェース名を取得
                    for x in line:
                        if not x == " ":
                            ifname += x
                        else:
                            line = line[len(ifname):]
                            break

                    self.logger.debug("ifname : %s", ifname)
                    # 入力されたインターフェース名と一致するかチェック
                    if not ifname == iface:
                        self.logger.error(
                            "input exist network interface name where "
                            + const.CONF_FILE + " at 'mld_esw_ifname'.")
                        self.end_process()

                if not ifdict.get(self.IF_KEY_MAC):
                    # MACアドレス検索
                    mac = mac_pat.search(line)
                    if mac:
                        ifdict[self.IF_KEY_MAC] = mac.group()
                        self.logger.debug("mac : %s", ifdict[self.IF_KEY_MAC])
                        continue

                if not ifdict.get(self.IF_KEY_IP6):
                    # IPv6リンクローカルアドレス検索
                    ip6 = ip6_pat.search(line)
                    if ip6:
                        ifdict[self.IF_KEY_IP6] = ip6.group()[:-3]  # "/64”を削除
                        self.logger.debug("ip6 : %s", ifdict[self.IF_KEY_IP6])
                        continue

            # 改行のみの行でifdictを確定
            else:
                if not ifdict.get(self.IF_KEY_MAC):
                    # MACアドレスのないインターフェース（loなど）が入力された場合
                    self.logger.error(
                        "input network interface name with " +
                        "mac address where " + const.CONF_FILE +
                        " at 'mld_esw_ifname'.")
                    self.end_process()
                if not ifdict.get(self.IF_KEY_IP6):
                    # IPv6リンクローカルアドレスのないインターフェースが入力された場合
                    self.logger.error(
                        "input network interface name with " +
                        "ipv6 link local address where " + const.CONF_FILE +
                        " at 'mld_esw_ifname'.")
                    self.end_process()
                break
        return ifdict

    # =========================================================================
    # calculate_qqic
    # =========================================================================
    def calculate_qqic(self, interval):
        self.logger.debug("")

        if interval < 128:
            return interval
        else:
            mant = 0
            exp = 0

            # Calculate the "mant" and the "exp"
            while ((interval >> (exp + 3)) > 0x1f):
                exp = exp + 1
            mant = (interval >> (exp + 3)) & 0xf
            return 0x80 | (exp << 4) | mant

    # =========================================================================
    # get_zmq_connect
    # =========================================================================
    def get_zmq_connect(self, configfile):
        self.logger.debug("")

        # 変数の初期化
        zmq_pub = None
        zmq_sub = None

        # ZMQタイプの読み込み
        settings = configfile.data[const.SETTING]
        zmq_type = settings[const.ZMQ_TYPE]

        # zmq_urlの設定
        zmq_url = zmq_type.lower() + const.URL_DELIMIT

        if zmq_type.lower() == const.CHECK_ZMQ_TYPE_IPC:
            # IPCによるSoket設定の読み込み
            config_zmq_ipc = configfile.data[const.ZMQ_IPC]
            zmq_pub = config_zmq_ipc[const.ZMQ_PUB]
            zmq_sub = config_zmq_ipc[const.ZMQ_SUB]
            # CHECK TMP FILE(SEND)
            self.check_exists_tmp(zmq_pub)
            # CHECK TMP FILE(RECV)
            self.check_exists_tmp(zmq_sub)
            # zmq_urlを設定し、返却
            return [zmq_url + zmq_pub, zmq_url + zmq_sub]

        elif zmq_type.lower() == const.CHECK_ZMQ_TYPE_TCP:
            # TCPによるSoket設定の読み込み
            config_zmq_tcp = configfile.data[const.ZMQ_TCP]
            zmq_sub = config_zmq_tcp[const.MLD_SERVER_IP]
            zmq_sub_list = zmq_sub.split(const.PORT_DELIMIT)
            # zmq_subのポート設定を取得し、zmq_pubのIPアドレスに付与
            zmq_pub = const.SEND_IP + const.PORT_DELIMIT \
                + zmq_sub_list[1]
            # zmq_urlを設定し、返却
            return [zmq_url + zmq_pub, zmq_url + zmq_sub]

        else:
            self.logger.error("self.config[%s]:%s", const.ZMQ_TYPE, zmq_type)
            raise Exception.message("self.config[%s]:%s",
                                    const.ZMQ_TYPE, zmq_type)

    # ==================================================================
    # check_exists_tmp
    # ==================================================================
    def check_exists_tmp(self, filename):
        self.logger.debug("")

        if os.path.exists(filename):
            self.logger.debug("[tmp filename]:%s", filename)
            return True

        else:
            dirpath = os.path.dirname(filename)
            if os.path.isdir(dirpath):
                f = open(filename, "w")
                f.write("")
                f.close()
                self.logger.info("create [file]:%s", filename)
            else:
                os.makedirs(dirpath)
                f = open(filename, "w")
                f.write("")
                f.close()
                self.logger.info("create [dir]:%s, [file]:%s",
                                 dirpath, filename)

    # =========================================================================
    # create_socket
    # =========================================================================
    def create_socket(self, sendpath, recvpath):
        self.logger.debug("")

        ctx = zmq.Context()

        # SEND SOCKET CREATE
        self.send_sock = ctx.socket(zmq.PUB)
        self.send_sock.bind(sendpath)
        self.logger.info("[SendSocket]:%s", sendpath)

        # RECV SOCKET CREATE
        self.recv_sock = ctx.socket(zmq.SUB)
        self.recv_sock.connect(recvpath)
        self.recv_sock.setsockopt(zmq.SUBSCRIBE, "")
        self.logger.info("[RecvSocket]:%s", recvpath)

    # ==================================================================
    # send_mldquery_regularly
    # ==================================================================
    def send_mldquery_regularly(self):
        self.logger.debug("")

        requraly_query_type = self.config[const.REGURALY_QUERY_TYPE]
        reguraly_query_interval = self.config[const.REGURALY_QUERY_INTERVAL]
        mc_query_interval = self.config[const.MC_QUERY_INTERVAL]

        # General Query
        if requraly_query_type == self.GENERAL_QUERY:
            self.logger.debug("create general query")
            mc_info = {const.MC_TAG_MC_ADDR: "::", const.MC_TAG_SERV_IP: None}
            while self.SEND_LOOP:
                self.send_mldquery([mc_info])
                # タイムアウトチェック
                self.check_user_timeout()
                time.sleep(reguraly_query_interval - self.QUERY_QRV)

        # Specific Query
        elif requraly_query_type == self.SPECIFIC_QUERY:
            self.logger.debug("create specific query")
            next_interval = Value(ctypes.c_bool, False)
            send_count = 1

            while self.SEND_LOOP:
                query_proc = Process(
                    target=self.wait_query_interval,
                    args=(next_interval, reguraly_query_interval))
                query_proc.daemon = True
                query_proc.start()
                self.logger.debug(
                    "next_interval : %s", str(next_interval.value))
                self.send_mldquery(
                    self.mc_info_list, mc_query_interval, next_interval)
                # タイムアウトチェック
                self.check_user_timeout()

                # 定期送信クエリの送信間隔が過ぎていない場合は待ち
                if not next_interval.value:
                    self.logger.debug(
                        "waiting query interval(%d sec)...",
                        reguraly_query_interval)
                    query_proc.join()

                next_interval.value = False
                self.logger.debug("send_count : %d", send_count)
                query_proc.terminate()
                send_count += 1

    # ==================================================================
    # wait_query_interval
    # ==================================================================
    def wait_query_interval(self, next_interval, reguraly_query_interval):
        self.logger.debug("")
        self.logger.debug(
            "waiting %d sec...", reguraly_query_interval)
        time.sleep(reguraly_query_interval)
        self.logger.debug("waited %d sec", reguraly_query_interval)
        next_interval.value = True
        self.logger.debug("update next_interval : %s",
                          str(next_interval.value))

    # ==================================================================
    # send_mldquery
    # ==================================================================
    def send_mldquery(self, mc_info_list, wait_time=0, next_interval=None):
        self.logger.debug("")

        vid = self.config[const.C_TAG_ID]
        for mc_info in mc_info_list:
            # 全体の待ち時間が経過した場合は処理中断（定期送信時のみ）
            if next_interval and next_interval.value:
                self.logger.debug("updated next_interval : %s",
                                  str(next_interval.value))
                return -1

            self.logger.debug("mc_addr, serv_ip : %s, %s",
                              mc_info[const.MC_TAG_MC_ADDR],
                              mc_info[const.MC_TAG_SERV_IP])
            mld = self.create_mldquery(
                mc_info[const.MC_TAG_MC_ADDR], mc_info[const.MC_TAG_SERV_IP])
            sendpkt = self.create_packet(vid, mld)

            # 信頼性変数QRV回送信する
            for i in range(self.QUERY_QRV):
                self.send_packet_to_sw(
                    sendpkt, mc_info[const.MC_TAG_MC_ADDR], vid)
                time.sleep(1)

            # 最後のmcアドレス情報以外は送信待ちする
            if not mc_info == mc_info_list[-1]:
                self.logger.debug("waiting %d sec...", wait_time)
                time.sleep(wait_time)

    # ==================================================================
    # create_mldquery
    # ==================================================================
    def create_mldquery(self, mc_address, mc_serv_ip):
        self.logger.debug("")

        query = icmpv6.mldv2_query(
            address=str(mc_address),
            srcs=[str(mc_serv_ip)] if mc_serv_ip else None,
            maxresp=self.QUERY_MAX_RESPONSE, qrv=self.QUERY_QRV,
            qqic=self.QQIC)
        self.logger.debug("created query : %s", str(query))
        return query

    # ==================================================================
    # create_mldreport
    # ==================================================================
    def create_mldreport(self, mc_address, mc_serv_ip, report_types):
        self.logger.debug("")

        record_list = []
        for report_type in report_types:
            record_list.append(
                icmpv6.mldv2_report_group(
                    type_=report_type, address=mc_address,
                    srcs=[mc_serv_ip]))

        report = icmpv6.mldv2_report(records=record_list)
        self.logger.debug("created report : %s", str(report))
        return report

    # ==================================================================
    # create_packet
    # ==================================================================
    def create_packet(self, vid, mld):
        self.logger.debug("")

        # VLAN
        vln = vlan.vlan(vid=vid, ethertype=ether.ETH_TYPE_IPV6)

        # Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6, data=[
            ipv6.option(type_=5, len_=2, data="\x00\x00"),
            ipv6.option(type_=1, len_=0)])]

        # MLDV2_Query
        if type(mld) == icmpv6.mldv2_query:
            # ETHER
            eth = ethernet.ethernet(
                ethertype=ether.ETH_TYPE_8021Q,
                src=self.ifinfo[self.IF_KEY_MAC], dst=self.QUERY_DST)

            # IPV6 with ExtensionHeader
            ip6 = ipv6.ipv6(
                src=self.ifinfo[self.IF_KEY_IP6], dst=self.QUERY_DST_IP,
                hop_limit=1, nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

            # MLD Query
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLD_LISTENER_QUERY, data=mld)

        # MLDV2_Report
        elif type(mld) == icmpv6.mldv2_report:
            # ETHER
            eth = ethernet.ethernet(
                ethertype=ether.ETH_TYPE_8021Q,
                src=self.ifinfo[self.IF_KEY_MAC], dst=self.REPORT_DST)

            # IPV6 with ExtensionHeader
            ip6 = ipv6.ipv6(
                src=self.ifinfo[self.IF_KEY_IP6], dst=self.REPORT_DST_IP,
                hop_limit=1, nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

            # MLD Report
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        # ether - vlan - ipv6 - icmpv6 ( - mldv2 )
        sendpkt = eth / vln / ip6 / icmp6
        sendpkt.serialize()
        self.logger.debug("created packet(ryu) : %s", str(sendpkt))

        return sendpkt

    # ==================================================================
    # send_packet_to_sw
    # ==================================================================
    def send_packet_to_sw(self, ryu_packet, mc_addr, vid):
        self.logger.debug("")
        sendpkt = scapy_packet.Packet(ryu_packet.data)

        # send of scapy
        sendrecv.sendp(
            sendpkt, iface=self.config[const.MLD_ESW_IFNAME], verbose=0)
        self.logger.info(
            "send to switch. [multicast_address]:'%s' [c_tag_id]:%s ",
            mc_addr, vid)

    # ==================================================================
    # send_packet_to_ryu
    # ==================================================================
    def send_packet_to_ryu(self, packet):
        self.logger.debug("")

        # send of zeromq
        self.send_sock.send(cPickle.dumps(packet, protocol=0))
        self.logger.info("send to mld_controller.")

    # ==================================================================
    # analyse_receive_packet
    # ==================================================================
    def analyse_receive_packet(self, recvpkt):
        self.logger.debug("")

        try:
            dispatch_ = recvpkt.dispatch
            self.logger.debug("received [type_]: %s", str(dispatch_["type_"]))
            self.logger.debug("received [data]: %s", str(dispatch_["data"]))
            receive_type = dispatch_["type_"]

            if receive_type == const.CON_MAIN_DISPATCHER:
                self.set_switch_config(dispatch_)

            elif receive_type == const.CON_PACKET_IN:
                pkt_icmpv6 = dispatch_["data"]
                self.logger.debug("pkt_icmpv6 : " + str(pkt_icmpv6))

                # MLDv2 Report
                if pkt_icmpv6.type_ == icmpv6.MLDV2_LISTENER_REPORT:
                    self.logger.debug(
                        "MLDv2 Report : %s", str(pkt_icmpv6.data))
                    self.manage_user(dispatch_)

                # タイムアウトチェック
                self.check_user_timeout()

                # MLDv2 Query
                if pkt_icmpv6.type_ == icmpv6.MLD_LISTENER_QUERY:
                    self.logger.debug("MLDv2 Query : %s", str(pkt_icmpv6.data))
                    query = pkt_icmpv6.data
                    self.reply_proxy(query.address, query.srcs)

            else:
                self.logger.error(
                    "dispatch[type_]:Not Exist(%s)", dispatch_["type_"])

        except:
            self.logger.error(
                "%s ", traceback.print_exc())

    # ==================================================================
    # set_switch_config
    # ==================================================================
    def set_switch_config(self, dispatch_):
        self.logger.debug("")
        self.logger.debug("dispatch_[data] : " + str(dispatch_["data"]))

        # 初期設定をFlowModする
        datapathid = dispatch_["datapathid"]
        flowlist = self.flowmod_gen.initialize_flows(
            datapathid=datapathid,
            pbb_isid=self.switch_mld_info[const.SW_TAG_MLD_INFO_PBB_ISID],
            bvid=self.switch_mld_info[const.SW_TAG_MLD_INFO_BVID],
            ivid=self.switch_mld_info[const.SW_TAG_MLD_INFO_IVID])
        self.send_flowmod(flowlist)

    # ==================================================================
    # create_packetout
    # ==================================================================
    def create_packetout(self, datapathid, port, packet):
        self.logger.debug("")

        actions = [parser.OFPActionOutput(port=port)]
        pout = packet_out_data(
            datapathid=datapathid, in_port=ofproto_v1_3.OFPP_CONTROLLER,
            buffer_id=ofproto_v1_3.OFP_NO_BUFFER, actions=actions,
            data=packet)

        return pout

    # ==================================================================
    # check_user_timeout
    # ==================================================================
    def check_user_timeout(self):
        try:
            self.logger.debug("")
            self.logger.debug("ch_info : \n%s",
                              self.ch_info.get_channel_info())
            self.logger.debug("user_info_list : %s",
                              self.ch_info.get_user_info_list())

            if self.ch_info.channel_info:
                # 視聴情報のタイムアウト判定を行い、オーバーしているものは削除する
                timeout = time.time() - self.config[const.USER_TIME_OUT]
                self.logger.debug("timeout : %f", timeout)

                timeout_user = channel_user_info("", "", 0, 0, 0, timeout)
                # タイムアウトとなる時間を持ったユーザを挿入する箇所を取得
                idx = self.ch_info.find_insert_point(timeout_user)
                self.logger.debug("idx : %s", str(idx))
                if idx > 0:
                    # 挿入箇所がuser_info_listの先頭でない場合、それ以前のユーザを削除
                    for i in range(idx):
                        del_user_info = \
                            self.ch_info.user_info_list[idx - i - 1]
                        self.logger.debug("timeout user : \n%s",
                                          del_user_info.get_user_info())

                        # ユーザの削除
                        reply_type = self.ch_info.remove_ch_info(
                            del_user_info.mc_addr, del_user_info.serv_ip,
                            del_user_info.datapathid, del_user_info.port_no,
                            del_user_info.cid)

                        # 削除が行われた場合
                        if not reply_type == const.CON_REPLY_NOTHING:

                            # SpecificQueryを生成し、エッジスイッチに送信
                            mc_info = {
                                const.MC_TAG_MC_ADDR: del_user_info.mc_addr,
                                const.MC_TAG_SERV_IP: del_user_info.serv_ip}
                            send_thre = threading.Thread(
                                target=self.send_mldquery,
                                name="SendQueryThread", args=[[mc_info], ])
                            send_thre.daemon = True
                            send_thre.start()

                            self.reply_to_ryu(
                                del_user_info.mc_addr, del_user_info.serv_ip,
                                del_user_info.datapathid,
                                del_user_info.port_no, reply_type)

                    self.logger.debug("ch_info : \n%s",
                                      self.ch_info.get_channel_info())
                    self.logger.debug("user_info_list : \n%s",
                                      self.ch_info.get_user_info_list())

                else:
                    self.logger.debug("timeout users are nothing.")

            else:
                self.logger.debug("ch_info is nothing.")

        except:
            self.logger.error("%s ", traceback.print_exc())

    # ==================================================================
    # reply_proxy
    # ==================================================================
    def reply_proxy(self, mc_addr, srcs):
        self.logger.debug("")

        # ルータからの定期Queryに対し視聴情報を返却する
        if not self.ch_info.channel_info:
            # 未視聴状態の場合は何もしない
            self.logger.debug("No one shows any channels.")
            return -1

        vid = self.config[const.C_TAG_ID]
        edge_sw_dpid = self.edge_switch[const.SW_TAG_DATAPATHID]
        edge_router_port = self.edge_switch[const.SW_TAG_EDGE_ROUTER_PORT]

        # General Queryの場合
        if mc_addr == "::" and srcs == []:
            # 視聴中のMCグループ毎にレポートを作成
            for mc_info in self.ch_info.channel_info.keys():
                self.send_packetout(
                    mc_info[0], mc_info[1], [icmpv6.MODE_IS_INCLUDE],
                    vid, edge_sw_dpid, edge_router_port)

        # Specific Queryの場合
        else:
            # Specific Queryでsrcが入っていない場合
            if srcs == []:
                self.logger.info("this query has no Source Address.")

            # 対象マルチキャストアドレスを視聴中のユーザがいればレポートを作成
            elif (mc_addr, srcs[0]) in self.ch_info.channel_info:
                self.send_packetout(
                    mc_addr, srcs[0], [icmpv6.MODE_IS_INCLUDE],
                    vid, edge_sw_dpid, edge_router_port)

            # 対象マルチキャストアドレスを視聴中のユーザがいない場合
            else:
                self.logger.debug("No one shows this channel[%s].", mc_addr)

    # ==================================================================
    # send_packetout
    # ==================================================================
    def send_packetout(self, mc_addr, serv_ip, report_type, vid,
                       datapathid, port):
        self.logger.debug("")

        mld = self.create_mldreport(
            mc_address=mc_addr, mc_serv_ip=serv_ip, report_types=report_type)
        # packetのsrcはMLD処理部のものを使用する
        sendpkt = self.create_packet(vid, mld)
        # エッジスイッチにp-out
        pout = self.create_packetout(datapathid=datapathid,
                                     port=port, packet=sendpkt)
        packetout = dispatch(
            type_=const.CON_PACKET_OUT, datapathid=datapathid, data=pout)
        self.logger.debug("packetout: %s", str(packetout))
        self.send_packet_to_ryu(packetout)

    # ==================================================================
    # manage_user
    # ==================================================================
    def manage_user(self, dispatch_):
        self.logger.debug("")

        mldv2_report = dispatch_["data"].data
        target_switch = dispatch_["datapathid"]
        in_port = dispatch_["in_port"]
        cid = dispatch_["cid"]

        for report in mldv2_report.records:

            address = report.address
            src = report.srcs[0] if report.srcs else ""
            report_type = report.type_
            self.logger.debug("report : " + str(report))

            # Reportの内容により、更新が必要な視聴情報を更新する
            reply_type = self.update_user_info(
                address, src, target_switch, in_port, cid, report_type)

            if reply_type == const.CON_REPLY_NOTHING:
                # Flow追加削除なしの場合何もしない
                self.logger.debug("reply_type : CON_REPLY_NOTHING")
                continue
            else:
                # reply_typeにより、Flowmod、Packetoutを生成し、ryuに返却する
                self.reply_to_ryu(
                    address, src, target_switch, in_port, reply_type)

    # ==================================================================
    # update_user_info
    # ==================================================================
    def update_user_info(
            self, address, src, target_switch, in_port, cid, report_type):
        try:
            self.logger.debug("")

            self.logger.debug("report_type : %s", str(report_type))
            self.logger.debug("datapath, in_port, cid : %s, %s, %s",
                              target_switch, in_port, cid)
            self.logger.debug("self.ch_info : %s",
                              self.ch_info.get_channel_info())
            self.logger.debug("user_info_list : %s",
                              self.ch_info.get_user_info_list())

            # MODE_IS_EXCLUDE
            # CHANGE_TO_INCLUDE_MODE の場合は何もしない
            if report_type in [
                    icmpv6.CHANGE_TO_INCLUDE_MODE, icmpv6.MODE_IS_EXCLUDE]:
                self.logger.debug("report_type : %s", report_type)
                reply_type = const.CON_REPLY_NOTHING

            # CHANGE_TO_EXCLUDE_MODE:INFOメッセージ出力
            elif report_type == icmpv6.CHANGE_TO_EXCLUDE_MODE:
                self.logger.info("input server_ip when VLC started.")
                reply_type = const.CON_REPLY_NOTHING

            else:
                # multicast_info.jsonに存在しないmcアドレスとサーバIPの組み合わせが指定された場合
                if not (address, src) in self.mc_info_dict:
                    self.logger.info(
                        "this multicast address[%s] and server ip[%s] %s",
                        address, src, "is not exist multicast_info.json.")
                    reply_type = const.CON_REPLY_NOTHING

                # ALLOW_NEW_SOURCES：視聴情報に追加
                elif report_type == icmpv6.ALLOW_NEW_SOURCES:
                    self.logger.debug("ALLOW_NEW_SOURCES")
                    reply_type = self.ch_info.update_ch_info(
                        mc_addr=address, serv_ip=src,
                        datapathid=target_switch, port_no=in_port, cid=cid)
                    self.logger.debug("reply_type : %s", reply_type)
                    self.logger.debug("added self.ch_info : %s",
                                      self.ch_info.get_channel_info())
                    self.logger.debug("added user_info_list : %s",
                                      self.ch_info.get_user_info_list())

                # BLOCK_OLD_SOURCES：視聴情報から削除
                elif report_type == icmpv6.BLOCK_OLD_SOURCES:
                    self.logger.debug("BLOCK_OLD_SOURCES")
                    reply_type = self.ch_info.remove_ch_info(
                        mc_addr=address, serv_ip=src,
                        datapathid=target_switch, port_no=in_port, cid=cid)

                    if reply_type is not None:
                        # 削除が行われた場合
                        self.logger.debug("reply_type : %s", reply_type)
                        self.logger.debug("removed self.ch_info : %s",
                                          self.ch_info.get_channel_info())

                        # SpecificQueryを生成し、エッジスイッチに送信
                        mc_info = {const.MC_TAG_MC_ADDR: address,
                                   const.MC_TAG_SERV_IP: src}
                        send_thre = threading.Thread(
                            target=self.send_mldquery,
                            name="SendQueryThread", args=[[mc_info], ])
                        send_thre.daemon = True
                        send_thre.start()
                    else:
                        # 削除が行われなかった場合
                        reply_type = const.CON_REPLY_NOTHING

                # MODE_IS_INCLUDE：視聴情報に存在するか確認
                elif report_type == icmpv6.MODE_IS_INCLUDE:
                    self.logger.debug("MODE_IS_INCLUDE")

                    # 視聴情報のタイマ更新
                    reply_type = self.ch_info.update_ch_info(
                        mc_addr=address, serv_ip=src,
                        datapathid=target_switch, port_no=in_port, cid=cid)
                    self.logger.debug("updated self.ch_info : %s",
                                      self.ch_info.get_channel_info())
                    self.logger.debug("updated user_info_list : %s",
                                      self.ch_info.get_user_info_list())

            return reply_type

        except:
            self.logger.error("%s ", traceback.print_exc())
            return const.CON_REPLY_NOTHING

    # ==================================================================
    # reply_to_ryu
    # ==================================================================
    def reply_to_ryu(self, address, src, target_switch, in_port, reply_type):
        # ryuに返却するデータ(flowmod,packetoutの要素)を作成し、送信する
        self.logger.debug("")

        # パケットアウトに必要な情報を取得
        vid = self.config[const.C_TAG_ID]
        edge_switch_dpid = self.edge_switch[const.SW_TAG_DATAPATHID]
        edge_switch_port = self.edge_switch[const.SW_TAG_EDGE_ROUTER_PORT]

        # マルチキャストアドレスに対応するpbb_isidとividを抽出
        mc_info = self.mc_info_dict[address, src]
        pbb_isid = mc_info["pbb_isid"]
        ivid = mc_info["ivid"]
        mc_info_type = mc_info["type"]

        # 視聴情報からbvidを特定する
        bvid = None
        if self.ch_info.channel_info and \
                (address, src) in self.ch_info.channel_info:
            listening_switch = self.ch_info.channel_info[
                (address, src)].keys()
            # datapathidの昇順に":"でつなぐ
            bvid_key = ":".join(map(str, sorted(listening_switch)))
            self.logger.debug("bvid_key : %s", bvid_key)
            bvid = self.bvid_variation[bvid_key]
        else:
            # 全く視聴されていない（離脱によって視聴ユーザがいなくなった）場合
            bvid = -1

        self.logger.debug("pbb_isid, ivid, bvid : %s, %s, %s",
                          pbb_isid, ivid, bvid)

        # Flow追加の場合
        if reply_type == const.CON_REPLY_ADD_MC_GROUP:
            # MCグループの追加
            self.logger.debug("reply_type : CON_REPLY_ADD_MC_GROUP")
            flowlist = self.flowmod_gen.start_mg(
                multicast_address=address, datapathid=target_switch,
                portno=in_port,
                mc_ivid=self.switch_mc_info[const.SW_TAG_MC_INFO_IVID],
                ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            self.send_flowmod(flowlist)

            # ベストエフォートの場合のみ
            if mc_info_type == self.BEST_EFFORT:
                report_types = [icmpv6.ALLOW_NEW_SOURCES,
                                icmpv6.CHANGE_TO_INCLUDE_MODE]
                self.send_packetout(
                    address, src, report_types, vid,
                    edge_switch_dpid, edge_switch_port)

        elif reply_type == const.CON_REPLY_ADD_SWITCH:
            # SWの追加
            self.logger.debug("reply_type : CON_REPLY_ADD_SWITCH")
            flowlist = self.flowmod_gen.add_datapath(
                multicast_address=address, datapathid=target_switch,
                portno=in_port, ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            self.send_flowmod(flowlist)

        elif reply_type == const.CON_REPLY_ADD_PORT:
            # ポートの追加
            self.logger.debug("reply_type : CON_REPLY_ADD_PORT")
            flowlist = self.flowmod_gen.add_port(
                multicast_address=address, datapathid=target_switch,
                portno=in_port, ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            self.send_flowmod(flowlist)

        # Flow削除の場合
        elif reply_type == const.CON_REPLY_DEL_MC_GROUP:
            # MCアドレスの削除
            self.logger.debug("reply_type : CON_REPLY_DEL_MC_GROUP")
            # ベストエフォートの場合のみ
            if mc_info_type == self.BEST_EFFORT:
                self.send_packetout(
                    address, src, [icmpv6.BLOCK_OLD_SOURCES], vid,
                    edge_switch_dpid, edge_switch_port)

            flowlist = self.flowmod_gen.remove_mg(
                multicast_address=address, datapathid=target_switch,
                portno=in_port,
                mc_ivid=self.switch_mc_info[const.SW_TAG_MC_INFO_IVID],
                ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            self.send_flowmod(flowlist)

        elif reply_type == const.CON_REPLY_DEL_SWITCH:
            # SWの削除
            self.logger.debug("reply_type : CON_REPLY_DEL_SWITCH")
            flowlist = self.flowmod_gen.remove_datapath(
                multicast_address=address, datapathid=target_switch,
                portno=in_port, ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            self.send_flowmod(flowlist)

        elif reply_type == const.CON_REPLY_DEL_PORT:
            # ポートの削除
            self.logger.debug("reply_type : CON_REPLY_DEL_PORT")
            flowlist = self.flowmod_gen.remove_port(
                multicast_address=address, datapathid=target_switch,
                portno=in_port, ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            self.send_flowmod(flowlist)

    # ==================================================================
    # send_flowmod
    # ==================================================================
    def send_flowmod(self, flowlist):
        self.logger.debug("")

        flowmod = dispatch(
            type_=const.CON_FLOW_MOD, datapathid=None, data=flowlist)
        self.logger.debug("flowmod[data] : %s", str(flowmod["data"]))
        self.send_packet_to_ryu(flowmod)

    # ==================================================================
    # receive_from_ryu
    # ==================================================================
    def receive_from_ryu(self):
        self.logger.debug("")
        while self.RECV_LOOP:
            # receive of zeromq
            if self.recv_sock.poll(self.ZMQ_POLL_INTERVAL) != 0:
                recvpkt = self.recv_sock.recv()
                self.analyse_receive_packet(cPickle.loads(recvpkt))
                self.logger.debug("waiting packet...")

    # ==================================================================
    # end_process
    # ==================================================================
    def end_process(self):
        self.SEND_LOOP = False
        self.RECV_LOOP = False
        sys.exit()


if __name__ == "__main__":
    mld_proc = None
    try:
        mld_proc = mld_process()
        # Query定期送信スレッド
        send_thre = threading.Thread(
            target=mld_proc.send_mldquery_regularly, name="SendRegThread")
        send_thre.daemon = True
        send_thre.start()
        # パケット受信処理
        mld_proc.receive_from_ryu()

    except KeyboardInterrupt:
        # ctrl-cが入力されたら終了
        if mld_proc:
            mld_proc.end_process()
