# coding: utf-8
# zmq install
#  >sudo apt-get install libzmq-dev
#  >sudo apt-get install python-zmq

from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.lib import hub
from scapy import sendrecv
from scapy import packet as scapy_packet
from eventlet import patcher
from multiprocessing import Process, Value
import os
import logging
import logging.config
import cPickle
import zmq
import sys
import time
import ctypes
hub.patch()

from icmpv6_extend import icmpv6_extend
from user_manage import channel_info, channel_user_info
from flowmod_gen import flow_mod_generator

COMMON_PATH = "../../common/"
sys.path.append(COMMON_PATH)
from zmq_dispatch import dispatch
from read_json import read_json
import mld_const


# ======================================================================
# mld_process
# ======================================================================
class mld_process():

    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    ADDRESS_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./address_info.csv"))
    MC_SERVICE_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./multicast_service_info.json"))

    # Queryの設定値
    QUERY_MAX_RESPONSE = 10000
    QUERY_QRV = 2

    org_thread = patcher.original("threading")
    org_thread_time = patcher.original("time")

    CHECK_URL_IPC = "ipc://"

    def __init__(self):
        # ロガーの設定
        logging.config.fileConfig(COMMON_PATH + "logconf.ini",
                                  disable_existing_loggers=False)
        self.logger = logging.getLogger(__name__)
        self.logger.debug("")

        # ループフラグの設定
        self.loop_flg = True

        # 視聴情報初期化
        self.ch_info = channel_info()

        # 設定情報読み込み
        config = read_json(COMMON_PATH + "config.json")
        self.logger.info("config_info : %s", str(config.data))
        self.config = config.data["settings"]

        # ipc = self.config["ipc_url"]
        # send_path = self.config["ipc_ryu-mld"]
        # recv_path = self.config["ipc_mld-ryu"]
        zmq_url = self.config["mld_url"]
        send_path = self.config["mld_send_zmq"]
        recv_path = self.config["mld_recv_zmq"]

        # アドレス情報読み込み
        self.addressinfo = []
        for line in open(self.ADDRESS_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                columns = list(line[:-1].split(","))
                for column in columns:
                    self.addressinfo.append(column)
        self.logger.info("addressinfo : %s", str(self.addressinfo))

        # スイッチ情報読み込み
        switches = read_json(COMMON_PATH + "switch_info.json")
        self.logger.info("switch_info : %s", str(switches.data))
        self.switch_mld_info = switches.data["switch_mld_info"]
        self.switch_mc_info = switches.data["switch_mc_info"]
        self.switches = switches.data["switches"]
        self.edge_switch = self.switches[0]

        # マルチキャスト情報読み込み
        mc_info = read_json(self.MC_SERVICE_INFO)
        self.logger.info("mc_info : %s", str(mc_info.data))
        self.mc_info_list = mc_info.data["mc_info"]

        # bvidパターン読み込み
        bvid_variation = read_json(COMMON_PATH + "bvid_variation.json")
        self.logger.info("bvid_variation : %s", str(bvid_variation.data))
        self.bvid_variation = bvid_variation.data["bvid_variation"]

        # ZeroMQ送受信用設定

        if zmq_url == self.CHECK_URL_IPC:
            # CHECK TMP FILE(SEND)
            self.check_exists_tmp(send_path)
            # CHECK TMP FILE(RECV)
            self.check_exists_tmp(recv_path)

        # ZeroMQ送受信用ソケット生成
        self.cretate_scoket(zmq_url + send_path, zmq_url + recv_path)

        # Flowmod生成用インスタンス
        self.flowmod_gen = flow_mod_generator(self.switches)

    # ==================================================================
    # check_exists_tmp
    # ==================================================================
    def check_exists_tmp(self, filename):
        self.logger.debug("")

        if os.path.exists(filename):
            return

        else:
            dirpath = os.path.dirname(filename)
            if os.path.isdir(dirpath):
                f = open(filename, "w")
                f.write("")
                f.close()
                self.logger.info("create file[%s]", filename)
            else:
                os.makedirs(dirpath)
                f = open(filename, "w")
                f.write("")
                f.close()
                self.logger.info("create dir[%s], file[%s]",
                                 dirpath, filename)

    # =========================================================================
    # cretate_scoket
    # =========================================================================
    def cretate_scoket(self, sendpath, recvpath):
        self.logger.debug("")

        ctx = zmq.Context()

        # SEND SOCKET CREATE
        self.send_sock = ctx.socket(zmq.PUB)
        self.send_sock.bind(sendpath)
        self.logger.debug("[SendSocket] %s", sendpath)

        # RECV SOCKET CREATE
        self.recv_sock = ctx.socket(zmq.SUB)
        self.recv_sock.connect(recvpath)
        self.recv_sock.setsockopt(zmq.SUBSCRIBE, "")
        self.logger.debug("[RecvSocket] %s", recvpath)

    # ==================================================================
    # send_mldquey_regularly
    # ==================================================================
    def send_mldquey_regularly(self):
        self.logger.debug("")

        # General Query
        if self.config["reguraly_query_type"] == "GQ":
            mc_info = {"mc_addr": "::", "serv_ip": None}
            while True:
                self.send_mldquery([mc_info])
                hub.sleep(
                    self.config["reguraly_query_interval"] - self.QUERY_QRV)

        # Specific Query
        elif self.config["reguraly_query_type"] == "SQ":
            next_interval = Value(ctypes.c_bool, False)
            send_count = 1

            while True:
                query_proc = Process(
                    target=self.wait_query_interval, args=(next_interval,))
                query_proc.start()
                self.logger.debug("next_interval : %s",
                                  str(next_interval.value))
                self.send_mldquery(self.mc_info_list,
                                   self.config["mc_query_interval"],
                                   next_interval)

                # 定期送信クエリの送信間隔が過ぎていない場合は待ち
                if not next_interval.value:
                    self.logger.debug("waiting query interval(%d sec)...",
                                      self.config["reguraly_query_interval"])
                    query_proc.join()

                next_interval.value = False
                self.logger.debug("send_count : %d", send_count)
                query_proc.terminate()
                send_count += 1

    # ==================================================================
    # wait_query_interval
    # ==================================================================
    def wait_query_interval(self, next_interval):
        self.logger.debug("")
        self.logger.debug("waiting %d sec...",
                          self.config["reguraly_query_interval"])
        hub.sleep(self.config["reguraly_query_interval"])
        self.logger.debug("waited %d sec",
                          self.config["reguraly_query_interval"])
        next_interval.value = True
        self.logger.debug("update next_interval : %s",
                          str(next_interval.value))

    # ==================================================================
    # send_mldquery
    # ==================================================================
    def send_mldquery(self, mc_info_list, wait_time=0, next_interval=None):
        self.logger.debug("")

        vid = self.config["c_tag_id"]
        for mc_info in mc_info_list:
            # 全体の待ち時間が経過した場合は処理中断（定期送信時のみ）
            if next_interval and next_interval.value:
                self.logger.debug("updated next_interval : %s",
                                  str(next_interval.value))
                return -1

            self.logger.debug("mc_addr, serv_ip : %s, %s",
                              mc_info["mc_addr"], mc_info["serv_ip"])
            mld = self.create_mldquery(
                mc_info["mc_addr"], mc_info["serv_ip"])
            sendpkt = self.create_packet(
                self.addressinfo, vid, mld)

            # 信頼性変数QRV回送信する
            for i in range(self.QUERY_QRV):
                self.send_packet_to_sw(sendpkt)
                hub.sleep(1)

            # 最後のmcアドレス情報以外は送信待ちする
            if not mc_info == mc_info_list[-1]:
                self.logger.debug("waiting %d sec...", wait_time)
                self.org_thread_time.sleep(wait_time)

    # ==================================================================
    # create_mldquery
    # ==================================================================
    def create_mldquery(self, mc_address, mc_serv_ip):
        self.logger.debug("")

        query = icmpv6.mldv2_query(
            address=str(mc_address),
            srcs=[str(mc_serv_ip)] if mc_serv_ip else None,
            maxresp=self.QUERY_MAX_RESPONSE, qrv=self.QUERY_QRV,
            qqic=self.config["reguraly_query_interval"])
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
    def create_packet(self, addressinfo, vid, mld):
        self.logger.debug("")

        # ETHER
        eth = ethernet.ethernet(
            ethertype=ether.ETH_TYPE_8021Q,
            src=addressinfo[0], dst=addressinfo[1])

        # VLAN
        vln = vlan.vlan(vid=vid, ethertype=ether.ETH_TYPE_IPV6)

        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6, data=[
            ipv6.option(type_=5, len_=2, data="\x00\x00"),
            ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(
            src=addressinfo[2], dst=addressinfo[3],
            hop_limit=1, nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

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
        self.logger.debug("created packet(ryu) : %s", str(sendpkt))

        return sendpkt

    # ==================================================================
    # send_packet_to_sw
    # ==================================================================
    def send_packet_to_sw(self, ryu_packet):
        self.logger.debug("")
        sendpkt = scapy_packet.Packet(ryu_packet.data)

        # send of scapy
        sendrecv.sendp(sendpkt)
        self.logger.debug("sent 1 packet to switch.")

    # ==================================================================
    # send_packet_to_ryu
    # ==================================================================
    def send_packet_to_ryu(self, packet):
        self.logger.debug("")

        # send of zeromq
        self.send_sock.send(cPickle.dumps(packet, protocol=0))
        self.logger.debug("sent 1 packet to ryu.")

    # ==================================================================
    # analyse_receive_packet
    # ==================================================================
    def analyse_receive_packet(self, recvpkt):
        self.logger.debug("")
        dispatch_ = recvpkt.dispatch
        self.logger.debug("received [type_]: %s", str(dispatch_["type_"]))
        self.logger.debug("received [data]: %s", str(dispatch_["data"]))
        receive_type = dispatch_["type_"]

        if receive_type == mld_const.CON_SWITCH_FEATURE:
            self.set_switch_config(dispatch_)

        elif receive_type == mld_const.CON_PACKET_IN:
            pkt_icmpv6 = dispatch_["data"]
            self.logger.debug("pkt_icmpv6 : " + str(pkt_icmpv6))

            # MLDv2 Query
            if pkt_icmpv6.type_ == icmpv6.MLD_LISTENER_QUERY:
                self.logger.debug("MLDv2 Query : %s", str(pkt_icmpv6.data))
                self.reply_proxy()

            # MLDv2 Report
            if pkt_icmpv6.type_ == icmpv6.MLDV2_LISTENER_REPORT:
                self.logger.debug("MLDv2 Report : %s",
                                  str(pkt_icmpv6.data))
                self.manage_user(dispatch_)

            # タイムアウトチェック
            self.check_user_timeout()

        else:
            self.logger.debug("received type : %s", dispatch_["type_"])

    # ==================================================================
    # set_switch_config
    # ==================================================================
    def set_switch_config(self, dispatch_):
        self.logger.debug("")

        # ファイルから読み込んだSWの情報から接続元SWがエッジか収容か判定し、
        # 初期設定をFlowModする
        target_switch = dispatch_["datapathid"]
        for switch in self.switches:
            if target_switch == switch["datapathid"]:
                # 初期Flow設定
                flowlist = []
                flowlist = self.flowmod_gen.initialize_flows(
                    datapathid=target_switch,
                    pbb_isid=self.switch_mld_info["pbb_isid"],
                    bvid=self.switch_mld_info["bvid"],
                    ivid=self.switch_mld_info["ivid"])
                flowmod = dispatch(
                    type_=mld_const.CON_FLOW_MOD,
                    datapathid=target_switch, data=flowlist)
                self.logger.debug("flowmod[data] : %s",
                                  str(flowmod["data"]))
                self.send_packet_to_ryu(flowmod)

    # ==================================================================
    # create_packetout
    # ==================================================================
    def create_packetout(self, datapathid, packet):
        self.logger.debug("")
        actions = [parser.OFPActionOutput(
            port=self.edge_switch["edge_router_port"])]
        pout = parser.OFPPacketOut(
            datapath=datapathid, in_port=ofproto_v1_3.OFPP_CONTROLLER,
            buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
            actions=actions, data=packet)
        return pout

    # ==================================================================
    # check_user_timeout
    # ==================================================================
    def check_user_timeout(self):
        self.logger.debug("")
        self.logger.debug("ch_info : \n%s", self.ch_info.get_channel_info())
        self.logger.debug("user_info_list : \n%s",
                          self.ch_info.get_user_info_list())

        if self.ch_info.channel_info:
            # 視聴情報のタイムアウト判定を行い、オーバーしているものは削除する
            timeout = time.time() - self.config["user_time_out"]
            self.logger.debug("timeout : %f", timeout)

            dummy_user_info = channel_user_info("", "", 0, 0, 0, timeout)
            idx = self.ch_info.find(
                self.ch_info.user_info_list, dummy_user_info, True)
            self.logger.debug("idx : %s", str(idx))
            if not idx == 0:
                for i in range(idx):
                    del_user_info = self.ch_info.user_info_list[idx - i - 1]
                    keys = del_user_info.user_info.keys()[0]
                    self.ch_info.remove_ch_info(
                        keys[0], keys[1], keys[2], keys[3], keys[4])

                    # TODO 削除後のQuery送信が必要か要確認

                self.logger.debug("ch_info : \n%s",
                                  self.ch_info.get_channel_info())
                self.logger.debug("user_info_list : \n%s",
                                  self.ch_info.get_user_info_list())
            else:
                self.logger.debug("timeout users are nothing.")

        else:
            self.logger.debug("ch_info is nothing.")

    # ==================================================================
    # reply_proxy
    # ==================================================================
    def reply_proxy(self):
        self.logger.debug("")

        # ルータからの定期Queryに対し視聴情報を返却する
        if not self.ch_info.channel_info:
            # 未視聴状態の場合は何もしない
            self.logger.info("No one shows any channels.")

        else:
            vid = self.config["c_tag_id"]
            # 視聴中のMCグループ毎にレポートを作成
            for mc_info in self.ch_info.channel_info.keys():
                report_type = [icmpv6.MODE_IS_INCLUDE]
                mld = self.create_mldreport(
                    mc_info[0], mc_info[1], report_type)
                # packetのsrcはMLD処理部のものを使用する
                sendpkt = self.create_packet(self.addressinfo, vid, mld)
                # エッジスイッチにp-out
                pout = self.create_packetout(
                    datapathid=self.edge_switch["datapathid"],
                    packet=sendpkt)
                packetout = dispatch(
                    type_=mld_const.CON_PACKET_OUT,
                    datapathid=self.edge_switch["datapathid"], data=pout)
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
            src = report.srcs[0]

            # Reportの内容により、更新が必要な視聴情報を更新する
            reply_type = self.update_user_info(
                address, src, target_switch, in_port, cid, report)

            if reply_type == mld_const.CON_REPLY_NOTHING:
                # Flow追加削除なしの場合何もしない
                self.logger.debug("reply_type : CON_REPLY_NOTHING")
            else:
                # reply_typeにより、Flowmod、Packetoutを生成し、ryuに返却する
                self.reply_to_ryu(
                    address, src, target_switch, in_port, reply_type)

    # ==================================================================
    # update_user_info
    # ==================================================================
    def update_user_info(
            self, address, src, target_switch, in_port, cid, report):
        self.logger.debug("")

        self.logger.debug("report : %s", str(report))
        self.logger.debug("datapath, in_port, cid : %s, %s, %s",
                          target_switch, in_port, cid)
        self.logger.debug("self.ch_info : %s",
                          self.ch_info.get_channel_info())

        # ALLOW_NEW_SOURCES：視聴情報に追加
        if report.type_ == icmpv6.ALLOW_NEW_SOURCES:
            self.logger.debug("ALLOW_NEW_SOURCES")
            reply_type = self.ch_info.add_ch_info(
                mc_addr=address, serv_ip=src,
                datapathid=target_switch, port_no=in_port, cid=cid)
            self.logger.debug("reply_type : %s", reply_type)
            self.logger.debug("added self.ch_info : %s",
                              self.ch_info.get_channel_info())

        # BLOCK_OLD_SOURCES：視聴情報から削除
        elif report.type_ == icmpv6.BLOCK_OLD_SOURCES:
            self.logger.debug("BLOCK_OLD_SOURCES")
            reply_type = self.ch_info.remove_ch_info(
                mc_addr=address, serv_ip=src,
                datapathid=target_switch, port_no=in_port, cid=cid)
            self.logger.debug("reply_type : %s", reply_type)
            self.logger.debug("removed self.ch_info : %s",
                              self.ch_info.get_channel_info())

            # SpecificQueryを生成し、エッジスイッチに送信
            mc_info = {"mc_addr": address, "serv_ip": src}
            self.send_mldquery([mc_info])

        # MODE_IS_INCLUDE：視聴情報に存在するか確認
        elif report.type_ == icmpv6.MODE_IS_INCLUDE:
            self.logger.debug("MODE_IS_INCLUDE")

            # 視聴情報のタイマ更新
            user = self.ch_info.update_user_info_list(
                mc_addr=address, serv_ip=src,
                datapathid=target_switch, port_no=in_port, cid=cid)
            self.logger.debug("user_info_list : %s",
                              self.ch_info.get_user_info_list())

            if not user:
                # 更新対象ユーザが存在しなかった場合は視聴情報に追加する
                reply_type = self.ch_info.add_ch_info(
                    mc_addr=address, serv_ip=src,
                    datapathid=target_switch, port_no=in_port, cid=cid)
                self.logger.debug("added self.ch_info : %s",
                                  self.ch_info.get_channel_info())
            else:
                # 存在した場合はtimeの更新のみでryuへの返信はなし
                reply_type = mld_const.CON_REPLY_NOTHING

        # MODE_IS_EXCLUDE
        # CHANGE_TO_INCLUDE_MODE
        # CHANGE_TO_EXCLUDE_MODE の場合は何もしない
        else:
            self.logger.debug("report.type : %s", report.type_)
            reply_type = mld_const.CON_REPLY_NOTHING

        return reply_type

    # ==================================================================
    # reply_to_ryu
    # ==================================================================
    def reply_to_ryu(self, address, src, target_switch, in_port, reply_type):
        self.logger.debug("")
        flowlist = []
        pbb_isid = ""
        ivid = ""
        mc_info_type = ""
        bvid = ""
        vid = self.config["c_tag_id"]

        # マルチキャストアドレスに対応するpbb_isidとividを抽出
        for mc_info in self.mc_info_list:
            if mc_info["mc_addr"] == address and mc_info["serv_ip"] == src:
                pbb_isid = mc_info["pbb_isid"]
                ivid = mc_info["ivid"]
                mc_info_type = mc_info["type"]
                break

        # 視聴情報からbvidを特定する
        if self.ch_info.channel_info and \
                (address, src) in self.ch_info.channel_info:
            listening_switch = self.ch_info.channel_info[
                (address, src)].keys()
            bvid_key = ":".join(map(str, listening_switch))
            self.logger.debug("bvid_key : %s", bvid_key)
            for bvid_variation in self.bvid_variation:
                if bvid_key == bvid_variation["key"]:
                    bvid = bvid_variation["bvid"]
                    break
        else:
            # 当該mcグループが視聴されていない（離脱によって視聴ユーザがいなくなった）場合
            bvid = -1

        self.logger.debug("pbb_isid, ivid, bvid : %s, %s, %s",
                          pbb_isid, ivid, bvid)

        # Flow追加の場合
        if reply_type == mld_const.CON_REPLY_ADD_MC_GROUP:
            self.logger.debug("reply_type : CON_REPLY_ADD_MC_GROUP")
            flowlist = self.flowmod_gen.start_mg(
                multicast_address=address, datapathid=target_switch,
                portno=in_port, mc_ivid=self.switch_mc_info["ivid"],
                ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            flowmod = dispatch(
                type_=mld_const.CON_FLOW_MOD,
                datapathid=self.edge_switch["datapathid"], data=flowlist)
            self.logger.debug("flowmod[data] : %s", str(flowmod["data"]))

            self.send_packet_to_ryu(flowmod)

            # ベストエフォートの場合のみ
            if mc_info_type == "BE":
                # エッジスイッチへ投げるReportを作成
                report_types = [icmpv6.ALLOW_NEW_SOURCES,
                                icmpv6.CHANGE_TO_INCLUDE_MODE]
                mld_report = self.create_mldreport(
                    mc_address=address, mc_serv_ip=src,
                    report_types=report_types)
                packet = self.create_packet(
                    self.addressinfo, vid, mld_report)
                pout = self.create_packetout(
                    datapathid=self.edge_switch["datapathid"], packet=packet)
                packetout = dispatch(
                    type_=mld_const.CON_PACKET_OUT,
                    datapathid=self.edge_switch["datapathid"], data=pout)
                self.send_packet_to_ryu(packetout)

        elif reply_type == mld_const.CON_REPLY_ADD_SWITCH:
            self.logger.debug("reply_type : CON_REPLY_ADD_SWITCH")
            flowlist = self.flowmod_gen.add_datapath(
                multicast_address=address, datapathid=target_switch,
                portno=in_port, ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            flowmod = dispatch(
                type_=mld_const.CON_FLOW_MOD,
                datapathid=self.edge_switch["datapathid"], data=flowlist)
            self.logger.debug("flowmod[data] : %s", str(flowmod["data"]))
            self.send_packet_to_ryu(flowmod)

        elif reply_type == mld_const.CON_REPLY_ADD_PORT:
            self.logger.debug("reply_type : CON_REPLY_ADD_PORT")
            flowlist = self.flowmod_gen.add_port(
                multicast_address=address, datapathid=target_switch,
                portno=in_port, ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            flowmod = dispatch(
                type_=mld_const.CON_FLOW_MOD,
                datapathid=self.edge_switch["datapathid"], data=flowlist)
            self.logger.debug("flowmod[data] : %s", str(flowmod["data"]))
            self.send_packet_to_ryu(flowmod)

        # Flow削除の場合
        elif reply_type == mld_const.CON_REPLY_DEL_MC_GROUP:
            self.logger.debug("reply_type : CON_REPLY_DEL_MC_GROUP")
            # ベストエフォートの場合のみ
            if mc_info_type == "BE":
                # エッジスイッチへ投げるReportを作成
                report_types = [icmpv6.BLOCK_OLD_SOURCES]
                mld_report = self.create_mldreport(
                    mc_address=address, mc_serv_ip=src,
                    report_types=report_types)
                packet = self.create_packet(
                    self.addressinfo, vid, mld_report)
                pout = self.create_packetout(
                    datapathid=self.edge_switch["datapathid"], packet=packet)
                packetout = dispatch(
                    type_=mld_const.CON_PACKET_OUT,
                    datapathid=self.edge_switch["datapathid"], data=pout)
                self.send_packet_to_ryu(packetout)

            flowlist = self.flowmod_gen.remove_mg(
                multicast_address=address, datapathid=target_switch,
                portno=in_port, mc_ivid=self.switch_mc_info["ivid"],
                ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            flowmod = dispatch(
                type_=mld_const.CON_FLOW_MOD,
                datapathid=self.edge_switch["datapathid"], data=flowlist)
            self.logger.debug("flowmod[data] : %s", str(flowmod["data"]))
            self.send_packet_to_ryu(flowmod)

        elif reply_type == mld_const.CON_REPLY_DEL_SWITCH:
            self.logger.debug("reply_type : CON_REPLY_DEL_SWITCH")
            flowlist = self.flowmod_gen.remove_datapath(
                multicast_address=address, datapathid=target_switch,
                portno=in_port, ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            flowmod = dispatch(
                type_=mld_const.CON_FLOW_MOD,
                datapathid=self.edge_switch["datapathid"], data=flowlist)
            self.logger.debug("flowmod[data] : %s", str(flowmod["data"]))
            self.send_packet_to_ryu(flowmod)

        elif reply_type == mld_const.CON_REPLY_DEL_PORT:
            self.logger.debug("reply_type : CON_REPLY_DEL_PORT")
            flowlist = self.flowmod_gen.remove_port(
                multicast_address=address, datapathid=target_switch,
                portno=in_port, ivid=ivid, pbb_isid=pbb_isid, bvid=bvid)
            flowmod = dispatch(
                type_=mld_const.CON_FLOW_MOD,
                datapathid=self.edge_switch["datapathid"], data=flowlist)
            self.logger.debug("flowmod[data] : %s", str(flowmod["data"]))
            self.send_packet_to_ryu(flowmod)

    # ==================================================================
    # receive_from_ryu
    # ==================================================================
    def receive_from_ryu(self):
        self.logger.debug("")
        while self.loop_flg:
            self.logger.debug("waiting packet...")
            # receive of zeromq
            recvpkt = self.recv_sock.recv()
            self.analyse_receive_packet(cPickle.loads(recvpkt))
            hub.sleep(1)


if __name__ == "__main__":
    mld_proc = mld_process()
    # Query定期送信スレッド
    send_thre = mld_proc.org_thread.Thread(
        target=mld_proc.send_mldquey_regularly, name="SendRegThread")
    send_thre.start()
    # 定期送信開始待ち
    mld_proc.org_thread_time.sleep(1)
    # パケット受信スレッド
    hub.spawn(mld_proc.receive_from_ryu)
    while True:
        time.sleep(1)
