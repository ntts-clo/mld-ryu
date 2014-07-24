# coding: utf-8

import os
import sys
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

COMMON_PATH = "../../common/"
sys.path.append(COMMON_PATH)
from icmpv6_extend import icmpv6_extend
from zmq_dispatch import dispatch, packet_out_data
from zmq_dispatch import flow_mod_data
from read_json import read_json
import mld_const

import pdb


# =============================================================================
# 定数定義
# =============================================================================
# OpenFlowのバージョン
OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
# Socketタイプチェック用定数
CHECK_URL_IPC = "ipc://"
# ログファイル用定数
LOG_CONF = "logconf.ini"
# 設定ファイル用定数
CONF_FILE = "config.json"


# =============================================================================
# Ryu MLDコントローラー
# =============================================================================
class mld_controller(app_manager.RyuApp):

    # datapathidに紐付くmessageを保持する辞書定義
    dict_msg = {}

    def __init__(self, *args, **kwargs):
        # ログ設定ファイル読み込み
        logging.config.fileConfig(COMMON_PATH + LOG_CONF)
        self.logger = logging.getLogger(__name__)
        self.logger.debug("")

        super(mld_controller, self).__init__(*args, **kwargs)

        # システムモジュールのソケットに対しパッチを適用
        patcher.monkey_patch()

        # 設定情報の読み込み
        config = read_json(COMMON_PATH + CONF_FILE)
        self.logger.info("config_info : %s", str(config.data))
        self.config = config.data["settings"]
        self.SOCKET_TIME_OUT = self.config["socket_time_out"]

        # zmq設定情報の読み込み
        zmq_url = self.config["ofc_url"]
        send_path = self.config["ofc_send_zmq"]
        recv_path = self.config["ofc_recv_zmq"]

        # VLANチェックフラグの読み込み
        self.check_vlan_flg = self.config["check_vlan_flg"]

        # ループフラグの設定
        self.loop_flg = True

        if zmq_url == CHECK_URL_IPC:
            # CHECK TMP FILE(SEND)
            self.check_exists_tmp(send_path)
            # CHECK TMP FILE(RECV)
            self.check_exists_tmp(recv_path)

        # ZeroMQ送受信用ソケット生成
        self.cretate_scoket(zmq_url + send_path, zmq_url + recv_path)

        # mldからの受信スレッドを開始
        hub.spawn(self.receive_from_mld)

    # =========================================================================
    # check_exists_tmp
    # =========================================================================
    def check_exists_tmp(self, filename):
        self.logger.debug(filename)

        # ファイルの存在チェック
        if os.path.exists(filename):
            return True

        else:
            # ディレクトリの存在チェック
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
                self.logger.info("create dir[%s], file[%s]", dirpath, filename)

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
    # analyse_receive_packet
    # ==================================================================
    def analyse_receive_packet(self, recvpkt):
        self.logger.debug("")

        dispatch = recvpkt.dispatch

        self.logger.debug("ryu received dispatch : %s", str(dispatch))
        self.logger.debug("dict_msg : %s", self.dict_msg.items())

        # CHECK dispatch[type_]
        if dispatch["type_"] == mld_const.CON_FLOW_MOD:
            flowmodlist = dispatch["data"]
            self.logger.debug("FLOW_MOD[data] : %s", dispatch["data"])

            for flowmoddata in flowmodlist:
                self.logger.debug("[flowmoddata] : %s", flowmoddata)

                # CHECK dict_msg.datapathid=flowmoddata.datapathid
                if not flowmoddata.datapathid in self.dict_msg:
                    self.logger.info("dict_msg[datapathid:%s] = None \n",
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

            # CHECK dict_msg.datapathid=dispatch["datapathid"]
            if not dispatch["datapathid"] in self.dict_msg:
                self.logger.info("dict_msg[datapathid:%s] = None \n",
                                 dispatch["datapathid"])
                return False

            else:
                # dispatch["datapathid"]に紐付くmsgbaseを取得する
                datapathid = dispatch["datapathid"]
                msgbase = self.dict_msg[datapathid]
                recvpkt = dispatch["data"]
                self.logger.debug("PACKET_OUT[data] : %s \n", recvpkt.data)

                # PACKET_OUT生成
                packetout = self.create_packet_out(msgbase.datapath,
                                                   recvpkt)

                # PACKET_OUT送信
                self.send_msg_to_packetout(msgbase, packetout)

        else:
            self.logger.error("dispatch[type_] : Not Exist(%s) \n",
                             dispatch["type_"])
            return False

    # =========================================================================
    # create_flow_mod
    # =========================================================================
    def create_flow_mod(self, datapath, flowdata):
        self.logger.info("")

        # Create flow mod message.
        flowmod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,
                                        table_id=flowdata.table_id,
                                        command=flowdata.command,
                                        priority=flowdata.priority,
                                        out_port=flowdata.out_port,
                                        out_group=flowdata.out_group,
                                        match=flowdata.match,
                                        instructions=flowdata.instructions)

        self.logger.debug("flowdata [datapathid] : %s", flowdata.datapathid)
        self.logger.debug("flowdata [command] : %s", flowdata.command)
        self.logger.debug("flowdata [out_port] : %s", flowdata.out_port)
        self.logger.debug("flowdata [out_group] : %s", flowdata.out_group)
        self.logger.debug("flowdata [table_id] : %s", flowdata.table_id)
        self.logger.debug("flowdata [priority] : %s", flowdata.priority)
        self.logger.debug("flowdata [match] : %s", flowdata.match)
        self.logger.debug("flowdata [instructions] : %s",
                          flowdata.instructions)

        return flowmod

    # =========================================================================
    # create_packet_out
    # =========================================================================
    def create_packet_out(self, datapath, pktoutdata):
        self.logger.info("")

        # Create packetout message.
        packetout = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                        buffer_id=pktoutdata.buffer_id,
                                        in_port=pktoutdata.in_port,
                                        actions=pktoutdata.actions,
                                        data=pktoutdata.data.data)

        self.logger.debug("packetout [datapathid] : %s", pktoutdata.datapathid)
        self.logger.debug("packetout [in_port] : %s", pktoutdata.in_port)
        self.logger.debug("packetout [buffer_id] : %s", pktoutdata.buffer_id)
        self.logger.debug("packetout [actions] : %s", pktoutdata.actions)
        self.logger.debug("packetout [data].data : %s", pktoutdata.data)

        return packetout

    # =========================================================================
    # send_to_mld
    # =========================================================================
    def send_to_mld(self, dispatch_):
        self.logger.debug("")

        # send of zeromq
        self.send_sock.send(cPickle.dumps(dispatch_, protocol=0))
        self.logger.info("sent 1 to mld_process. \n")

    # =========================================================================
    # receive_from_mld
    # =========================================================================
    def receive_from_mld(self):
        self.logger.debug("")

        while self.loop_flg:
            hub.sleep(1)
            recvpkt = None
            try:
                recvpkt = self.recv_sock.recv(flags=zmq.NOBLOCK)
            except zmq.ZMQError, e:
                if e.errno == zmq.EAGAIN:
                    pass

                else:
                    self.logger.error("receive_from_mld. %s ", e)
                    raise e

            if recvpkt is not None:
                packet = cPickle.loads(recvpkt)
                self.analyse_receive_packet(packet)

    # =========================================================================
    # send_msg_to_flowmod
    # =========================================================================
    def send_msg_to_flowmod(self, msgbase, flowmod):
        self.logger.debug("")

        msgbase.datapath.send_msg(flowmod)

        self.logger.info("sent 1 packet to FlowMod. \n")

    # =========================================================================
    # send_msg_to_barrier_request
    # =========================================================================
    def send_msg_to_barrier_request(self, msgbase):
        self.logger.debug("")

        ofp_parser = msgbase.datapath.ofproto_parser
        barrier = ofp_parser.OFPBarrierRequest(msgbase.datapath)
        msgbase.datapath.send_msg(barrier)

        self.logger.info("OFPBarrierRequest.[dpid] : %s [xid] : %s \n",
                         msgbase.datapath.id, msgbase.datapath.xid)

    # =========================================================================
    # send_msg_to_packetout
    # =========================================================================
    def send_msg_to_packetout(self, msgbase, packetout):
        self.logger.debug("")

        msgbase.datapath.send_msg(packetout)

        self.logger.info("sent 1 packet to PacketOut. \n")

    # =========================================================================
    # _switch_features_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        self.logger.debug("")

        msg = ev.msg
        datapath = ev.msg.datapath
        self.logger.info("OFPSwitchFeatures.[ver] : %s [dpid] : %s [xid] : %s",
                          msg.version, msg.datapath.id, msg.datapath.xid)

        # CHECK Already send
        if not datapath.id in self.dict_msg:

            # set msg to Dictionary
            self.dict_msg[datapath.id] = msg

            dispatch_ = dispatch(type_=mld_const.CON_SWITCH_FEATURE,
                                    datapathid=datapath.id)

            self.logger.debug("dispatch[type_] : %s",
                              mld_const.CON_SWITCH_FEATURE)
            self.logger.debug("dispatch[datapathid] : %s", datapath.id)

            self.send_to_mld(dispatch_)

        else:
            self.logger.info("dict_msg[datapathid] : Already Exist(%s) \n",
                             datapath.id)
            return True

    # =========================================================================
    # packet_in_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.debug("")
        #pdb.set_trace()
        msg = ev.msg
        pkt = packet.Packet(msg.data)

        self.logger.info("OFPPacketIn.[ver] : %s [dpid] : %s [xid] : %s",
                          msg.version, msg.datapath.id, msg.datapath.xid)
        self.logger.debug("OFPPacketIn.[data] : %s \n", str(pkt))

        # CHECK VLAN
        pkt_vlan = None
        if self.check_vlan_flg in "True":
            pkt_vlan = pkt.get_protocol(vlan.vlan)
            if not pkt_vlan:
                self.logger.debug("# check vlan : None \n")

        # CHECK ICMPV6
        pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
        if not pkt_icmpv6:
            self.logger.debug("# check icmpv6 : None \n")
            return False

        # CHECK MLD TYPE
        if not pkt_icmpv6.type_ in [icmpv6.MLDV2_LISTENER_REPORT,
                                    icmpv6.MLD_LISTENER_QUERY]:
            self.logger.debug("# check icmpv6.TYPE : %s \n",
                              str(pkt_icmpv6.type_))
            return False

        # CHECK FILTER_MODE
        if pkt_icmpv6.type_ in [icmpv6.MLDV2_LISTENER_REPORT]:

            if pkt_icmpv6.data.record_num == 0:
                self.logger.debug("# check data.record_num : %s \n",
                                      str(pkt_icmpv6.data.record_num))
                return False

            for mldv2_report_group in pkt_icmpv6.data.records:

                if not mldv2_report_group.type_ \
                                        in [icmpv6.MODE_IS_INCLUDE,
                                            icmpv6.CHANGE_TO_INCLUDE_MODE,
                                            icmpv6.ALLOW_NEW_SOURCES,
                                            icmpv6.BLOCK_OLD_SOURCES]:
                    self.logger.debug("# check report_group.[type_] : %s \n",
                                      str(mldv2_report_group.type_))

        vid = pkt_vlan.vid if pkt_vlan else 0
        dispatch_ = dispatch(type_=mld_const.CON_PACKET_IN,
                               datapathid=msg.datapath.id,
                               cid=vid,
                               in_port=msg.match["in_port"],
                               data=pkt_icmpv6)

        self.logger.debug("dispatch [type_] : %s", mld_const.CON_PACKET_IN)
        self.logger.debug("dispatch [datapathid] : %s", msg.datapath.id)
        self.logger.debug("dispatch [cid] : %s", str(vid))
        self.logger.debug("dispatch [in_port] : %s", msg.match["in_port"])
        self.logger.debug("dispatch [data] : %s", pkt_icmpv6)

        self.send_to_mld(dispatch_)

    # =========================================================================
    # barrier_reply_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _barrier_reply_handler(self, ev):
        msg = ev.msg
        self.logger.info("OFPBarrierReply.[ver] : %s [dpid] : %s [xid] : %s",
                      msg.version, msg.datapath.id, msg.datapath.xid)
