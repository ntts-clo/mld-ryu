# coding: utf-8

import os
import sys
import traceback
import cPickle
import zmq
import logging

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, icmpv6, vlan
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from eventlet import patcher
from ryu.lib import hub
hub.patch()

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
COMMON_PATH = DIR_PATH + "/../../common/"
sys.path.append(COMMON_PATH)
from icmpv6_extend import icmpv6_extend
from zmq_dispatch import dispatch, packet_out_data
from zmq_dispatch import flow_mod_data
from read_json import read_json
import mld_const
import json
#import pdb #[breakpoint]pdb.set_trace()


# =============================================================================
# 定数定義
# =============================================================================
# OpenFlowのバージョン用定数
OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
# Socketタイプ用定数
CHECK_URL_IPC = "ipc://"
CHECK_URL_TCP = "tcp://"
# VLANチェックフラグ用定数
CHECK_VLAN_FLG = True
# ZMQ用定数
URL_DELIMIT = "://"
PORT_DELIMIT = ":"
SEND_IP = "0.0.0.0"

# 設定ファイルの定義名
SETTING = "settings"
ZMQ_IPC = "zmq_ipc"
ZMQ_TCP = "zmq_tcp"
ZMQ_MODE = "zmq_mode"
ZMQ_PUB = "mld_zmq"
ZMQ_SUB = "ofc_zmq"
OFC_SERVER_IP = "ofc_server_ip"


# =============================================================================
# Ryu MLDコントローラー
# =============================================================================
class mld_controller(app_manager.RyuApp):

    # datapathidに紐付くmessageを保持する辞書定義
    dict_msg = {}

    def __init__(self, *args, **kwargs):
        try:
            # ログ設定ファイル読み込み
            logging.config.fileConfig(COMMON_PATH + mld_const.RYU_LOG_CONF,
                                      disable_existing_loggers=False)
            self.logger = logging.getLogger(__name__)
            self.logger.debug("")

            super(mld_controller, self).__init__(*args, **kwargs)

            # システムモジュールのソケットに対しパッチを適用
            patcher.monkey_patch()

            # 設定情報の読み込み
            config = read_json(COMMON_PATH + mld_const.CONF_FILE)
            self.logger.info("%s:%s", mld_const.CONF_FILE,
                json.dumps(config.data, indent=4,
                           sort_keys=True, ensure_ascii=False))
            self.config = config.data[SETTING]

            # zmq設定情報の読み込み
            zmq_mode = self.config[ZMQ_MODE]
            self.zmq_pub = None
            self.zmq_sub = None

            # ループフラグの設定
            self.loop_flg = True

            # CHECK zmq用URL
            zmq_url = zmq_mode.lower() + URL_DELIMIT
            if self.check_url(zmq_url):
                # IPCによるSoket設定の読み込み
                self.config = config.data[ZMQ_IPC]
                self.zmq_pub = self.config[ZMQ_PUB]
                self.zmq_sub = self.config[ZMQ_SUB]
                # CHECK TMP FILE(SEND)
                self.check_exists_tmp(self.zmq_pub)
                # CHECK TMP FILE(RECV)
                self.check_exists_tmp(self.zmq_sub)
            else:
                # TCPによるSoket設定の読み込み
                self.config = config.data[ZMQ_TCP]
                self.zmq_sub = self.config[OFC_SERVER_IP]
                self.zmq_sub_list = self.zmq_sub.split(PORT_DELIMIT)
                self.zmq_pub = SEND_IP + PORT_DELIMIT + self.zmq_sub_list[1]

            # ZeroMQ送受信用ソケット生成
            self.create_socket(zmq_url + self.zmq_pub, zmq_url + self.zmq_sub)

            # mldからの受信スレッドを開始
            hub.spawn(self.receive_from_mld)

        except:
            self.logger.error("%s ", traceback.print_exc())

    # =========================================================================
    # _switch_features_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        self.logger.debug("")

        try:
            msg = ev.msg
            datapath = ev.msg.datapath
            self.logger.info("OFPSwitchFeatures.[ver]:%s [dpid]:%s [xid]:%s ",
                              msg.version, msg.datapath.id, msg.datapath.xid)

            # set msg to Dictionary
            self.dict_msg[datapath.id] = msg

            dispatch_ = dispatch(type_=mld_const.CON_SWITCH_FEATURE,
                                    datapathid=datapath.id)

            self.logger.debug("dispatch[type_]:%s",
                              mld_const.CON_SWITCH_FEATURE)
            self.logger.debug("dispatch[datapathid]:%s", datapath.id)

            self.send_to_mld(dispatch_)

        except:
            self.logger.error("%s ", traceback.print_exc())

    # =========================================================================
    # packet_in_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.debug("")
        try:
            msg = ev.msg
            pkt = packet.Packet(msg.data)

            self.logger.info("OFPPacketIn.[ver]:%s [dpid]:%s [xid]:%s",
                              msg.version, msg.datapath.id, msg.datapath.xid)
            self.logger.debug("OFPPacketIn.[data]:%s", str(pkt))

            # CHECK VLAN
            pkt_vlan = None
            if CHECK_VLAN_FLG:
                pkt_vlan = pkt.get_protocol(vlan.vlan)
                if not pkt_vlan:
                    self.logger.debug("check vlan:None \n")
                    return False

            # CHECK ICMPV6
            pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
            if not pkt_icmpv6:
                self.logger.debug("check icmpv6:None \n")
                return False

            # CHECK MLD TYPE
            if not pkt_icmpv6.type_ in [icmpv6.MLDV2_LISTENER_REPORT,
                                        icmpv6.MLD_LISTENER_QUERY]:
                self.logger.debug("check icmpv6.TYPE:%s \n",
                                  str(pkt_icmpv6.type_))
                return False

            # CHECK FILTER_MODE
            if pkt_icmpv6.type_ in [icmpv6.MLDV2_LISTENER_REPORT]:

                if pkt_icmpv6.data.record_num == 0:
                    self.logger.debug("check data.record_num:%s \n",
                                          str(pkt_icmpv6.data.record_num))
                    return False

                for mldv2_report_group in pkt_icmpv6.data.records:

                    if not mldv2_report_group.type_ \
                                            in [icmpv6.MODE_IS_INCLUDE,
                                                icmpv6.CHANGE_TO_INCLUDE_MODE,
                                                icmpv6.ALLOW_NEW_SOURCES,
                                                icmpv6.BLOCK_OLD_SOURCES]:
                        self.logger.debug("check report_group.[type_]:%s \n",
                                          str(mldv2_report_group.type_))

            # CHECK_VLAN_ID
            vid = pkt_vlan.vid if pkt_vlan else 0

            # SET dispatch
            dispatch_ = dispatch(type_=mld_const.CON_PACKET_IN,
                                   datapathid=msg.datapath.id,
                                   cid=vid,
                                   in_port=msg.match["in_port"],
                                   data=pkt_icmpv6)

            self.logger.debug("dispatch [type_]:%s", mld_const.CON_PACKET_IN)
            self.logger.debug("dispatch [datapathid]:%s", msg.datapath.id)
            self.logger.debug("dispatch [cid]:%s", str(vid))
            self.logger.debug("dispatch [in_port]:%s", msg.match["in_port"])
            self.logger.debug("dispatch [data]:%s", pkt_icmpv6)

            self.send_to_mld(dispatch_)

        except:
            self.logger.error("%s ", traceback.print_exc())

    # =========================================================================
    # barrier_reply_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _barrier_reply_handler(self, ev):
        try:
            msg = ev.msg
            self.logger.info("OFPBarrierReply.[ver]:%s [dpid]:%s [xid]:%s",
                          msg.version, msg.datapath.id, msg.datapath.xid)

        except:
            self.logger.error("%s ", traceback.print_exc())

    # =========================================================================
    # send_msg_to_flowmod
    # =========================================================================
    def send_msg_to_flowmod(self, msgbase, flowmod):
        self.logger.debug("")

        msgbase.datapath.send_msg(flowmod)

        self.logger.info("FlowMod.[dpid]:%s [xid]:%s",
                         msgbase.datapath.id, msgbase.datapath.xid)

    # =========================================================================
    # send_msg_to_barrier_request
    # =========================================================================
    def send_msg_to_barrier_request(self, msgbase):
        self.logger.debug("")

        ofp_parser = msgbase.datapath.ofproto_parser
        barrier = ofp_parser.OFPBarrierRequest(msgbase.datapath)
        msgbase.datapath.send_msg(barrier)

        self.logger.info("BarrierRequest.[dpid]:%s [xid]:%s",
                         msgbase.datapath.id, msgbase.datapath.xid)

    # =========================================================================
    # send_msg_to_packetout
    # =========================================================================
    def send_msg_to_packetout(self, msgbase, packetout):
        self.logger.debug("")

        msgbase.datapath.send_msg(packetout)

        self.logger.info("PacketOut.[dpid]:%s [xid]:%s",
                         msgbase.datapath.id, msgbase.datapath.xid)

    # ==================================================================
    # analyse_receive_packet
    # ==================================================================
    def analyse_receive_packet(self, recvpkt):
        self.logger.debug("")

        try:
            # mld_processの転送用データクラスを取得
            dispatch = recvpkt.dispatch

            self.logger.debug("ryu received dispatch:%s", str(dispatch))
            self.logger.debug("dict_msg:%s", self.dict_msg.items())

            # CHECK dispatch[type_]
            if dispatch["type_"] == mld_const.CON_FLOW_MOD:
                flowmodlist = dispatch["data"]
                self.logger.debug("FlowMod[data]:%s", dispatch["data"])

                for flowmoddata in flowmodlist:
                    self.logger.debug("[flowmoddata]:%s", flowmoddata)

                    # CHECK dict_msg.datapathid=flowmoddata.datapathid
                    if not flowmoddata.datapathid in self.dict_msg:
                        self.logger.error("FlowMod dict_msg[dpid:%s] = None",
                                         flowmoddata.datapathid)

                    else:
                        # flowmoddata.datapathidに紐付くmsgbaseを取得する
                        msgbase = self.dict_msg[flowmoddata.datapathid]

                        # FLOW_MOD生成
                        flowmod = self.create_flow_mod(msgbase.datapath,
                                                       flowmoddata)

                        # FLOW_MOD送信
                        self.send_msg_to_flowmod(msgbase, flowmod)

                        # BARRIER_REQUEST送信
                        self.send_msg_to_barrier_request(msgbase)

            elif dispatch["type_"] == mld_const.CON_PACKET_OUT:

                # CHECK dict_msg.datapathid=dispatch[datapathid]
                if not dispatch["datapathid"] in self.dict_msg:
                    self.logger.error("PacketOut dict_msg[dpid:%s] = None",
                                     dispatch["datapathid"])
                    return False

                else:
                    # dispatch[datapathid]に紐付くmsgbaseを取得する
                    datapathid = dispatch["datapathid"]
                    msgbase = self.dict_msg[datapathid]
                    recvpkt = dispatch["data"]
                    self.logger.debug("PACKET_OUT[data]:%s \n", recvpkt.data)

                    # PACKET_OUT生成
                    packetout = self.create_packet_out(msgbase.datapath,
                                                       recvpkt)

                    # PACKET_OUT送信
                    self.send_msg_to_packetout(msgbase, packetout)

            else:
                self.logger.error("dispatch[type_]:Not Exist(%s)",
                                 dispatch["type_"])
                return False

        except:
            self.logger.error("%s ", traceback.print_exc())

    # =========================================================================
    # create_flow_mod
    # =========================================================================
    def create_flow_mod(self, datapath, flowdata):
        self.logger.debug("")

        # Create flow mod message.
        flowmod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,
                                        table_id=flowdata.table_id,
                                        command=flowdata.command,
                                        priority=flowdata.priority,
                                        out_port=flowdata.out_port,
                                        out_group=flowdata.out_group,
                                        match=flowdata.match,
                                        instructions=flowdata.instructions)

        self.logger.debug("flowdata [datapathid]:%s", flowdata.datapathid)
        self.logger.debug("flowdata [command]:%s", flowdata.command)
        self.logger.debug("flowdata [out_port]:%s", flowdata.out_port)
        self.logger.debug("flowdata [out_group]:%s", flowdata.out_group)
        self.logger.debug("flowdata [table_id]:%s", flowdata.table_id)
        self.logger.debug("flowdata [priority]:%s", flowdata.priority)
        self.logger.debug("flowdata [match]:%s", flowdata.match)
        self.logger.debug("flowdata [instructions]:%s",
                          flowdata.instructions)

        return flowmod

    # =========================================================================
    # create_packet_out
    # =========================================================================
    def create_packet_out(self, datapath, pktoutdata):
        self.logger.debug("")

        # Create packetout message.
        packetout = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                        buffer_id=pktoutdata.buffer_id,
                                        in_port=pktoutdata.in_port,
                                        actions=pktoutdata.actions,
                                        data=pktoutdata.data.data)

        self.logger.debug("packetout [datapathid]:%s", pktoutdata.datapathid)
        self.logger.debug("packetout [in_port]:%s", pktoutdata.in_port)
        self.logger.debug("packetout [buffer_id]:%s", pktoutdata.buffer_id)
        self.logger.debug("packetout [actions]:%s", pktoutdata.actions)
        self.logger.debug("packetout [data].data:%s", pktoutdata.data)

        return packetout

    # =========================================================================
    # send_to_mld
    # =========================================================================
    def send_to_mld(self, dispatch_):
        self.logger.debug("")

        # send of zeromq
        self.send_sock.send(cPickle.dumps(dispatch_, protocol=0))
        self.logger.info("send to mld_process.")

    # =========================================================================
    # receive_from_mld
    # =========================================================================
    def receive_from_mld(self):
        self.logger.debug("")

        try:
            while self.loop_flg:
                recvpkt = None
                try:
                    recvpkt = self.recv_sock.recv(flags=zmq.NOBLOCK)
                except zmq.ZMQError, e:
                    if e.errno == zmq.EAGAIN:
                        pass

                    else:
                        self.logger.error("%s ", e)

                if recvpkt is not None:
                    self.logger.info("receive from mld_process.")
                    packet = cPickle.loads(recvpkt)
                    self.analyse_receive_packet(packet)
                else:
                    hub.sleep(1)

        except:
            self.logger.error("%s ", traceback.print_exc())

    # =========================================================================
    # check_url
    # =========================================================================
    def check_url(self, zmq_url):
        self.logger.debug("")

        if zmq_url == CHECK_URL_IPC:
            return True

        elif zmq_url == CHECK_URL_TCP:
            return False

        else:
            self.logger.error("self.config[%s]:%s", OFC_ZMQ_URL, zmq_url)
            raise Exception.message("self.config[%s]:%s", OFC_ZMQ_URL, zmq_url)

    # =========================================================================
    # check_exists_tmp
    # =========================================================================
    def check_exists_tmp(self, filename):
        self.logger.debug("")

        # ファイルの存在チェック
        if os.path.exists(filename):
            self.logger.debug("[tmp filename]:%s", filename)
            return True

        else:
            # ディレクトリの存在チェック
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
