# coding: utf-8

import os
import cPickle
import zmq
import logging

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, icmpv6, vlan
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from eventlet import patcher
from common.zmq_dispatch import dispatch
from common.zmq_dispatch import flow_mod_data
from common.mld_const import mld_const
from common.read_json import read_json


class mld_controller(app_manager.RyuApp):
    SOCKET_FLG = 1

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    org_thread = patcher.original("threading")
    org_thread_time = patcher.original("time")

    dic_msg = {}

    def __init__(self, *args, **kwargs):

        # システムモジュールのソケットに対しパッチを適用
        patcher.monkey_patch()

        # ログ設定ファイル読み込み
        logging.config.fileConfig("../../common/logconf.ini")
        self.logger = logging.getLogger(__name__)
        self.logger.debug("")

        super(mld_controller, self).__init__(*args, **kwargs)

        # 設定情報読み込み
        config = read_json("../../common/config.json")
        self.logger.info("config_info : %s", str(config.data))
        self.config = config.data["settings"]
        self.SOCKET_TIME_OUT = self.config["socket_time_out"]

        ipc = self.config["ipc_url"]
        send_path = self.config["ipc_ryu-mld"]
        recv_path = self.config["ipc_mld-ryu"]

        # CHECK TMP FILE(SEND)
        self.check_exists_tmp(send_path)

        # CHECK TMP FILE(RECV)
        self.check_exists_tmp(recv_path)

        # ソケット生成
        self.cretate_scoket(ipc + send_path, ipc + recv_path)

        # ReceiveThread
        recv_thread = self.org_thread.Thread(
                                    target=self.receive_from_mld,
                                    name="ReceiveThread")
        recv_thread.start()

    # =========================================================================
    # CRETATE SCOKET
    # =========================================================================
    def cretate_scoket(self, sendpath, recvpath):
        self.logger.debug("")

        ctx = zmq.Context()

        # SEND SOCKET CREATE
        self.send_sock = ctx.socket(zmq.PUB)
        self.send_sock.bind(sendpath)
        self.logger.debug("[SendSocket]IPC %s", sendpath)

        # RECV SOCKET CREATE
        self.recv_sock = ctx.socket(zmq.SUB) 
        self.recv_sock.connect(recvpath)
        self.recv_sock.setsockopt(zmq.SUBSCRIBE, "")
        self.logger.debug("[RecvSocket]IPC %s", recvpath)

    # ==================================================================
    # analyse_receive_packet
    # ==================================================================
    def analyse_receive_packet(self, recvpkt):
        self.logger.debug("")

        dispatch = recvpkt.dispatch
        self.logger.debug("ryu received dispatch : %s \n", str(dispatch))

        # CHECK dispatch[type_]
        if dispatch["type_"] == mld_const.CON_FLOW_MOD:
            flowmodlist = dispatch["data"]
            self.logger.debug("FLOW_MOD[data] : %s \n", dispatch["data"])

            for flowmoddata in flowmodlist:
                # flowmoddata["datapathid"]に紐付くmsgbaseを取得する
                ### TODO Debug mld_processの修正が完了したタイミングで
                ### flowmoddata["datapathid"]を実装する
                #msgbase = self.get_msgbase(flowmoddata["datapathid"])
                msgbase = self.get_msgbase(dispatch["datapathid"])
                if msgbase == None:
                    return False

                # FLOW_MOD生成
                flowmod = self.create_flow_mod(msgbase.datapath,
                                               flowmoddata)

                # FLOW_MOD送信
                self.send_msg_to_flowmod(msgbase, flowmod)

                # BARRIER_REQUEST送信
                result = self.send_msg_to_barrier_request(msgbase)
                self.logger.debug("Barrier_Request[xid] : %s \n ", result)

        elif dispatch["type_"] == mld_const.CON_PACKET_OUT:
            # dispatch["datapathid"]に紐付くmsgbaseを取得する
            msgbase = self.get_msgbase(dispatch["datapathid"])
            if msgbase == None:
                return False

            recvpkt = dispatch["data"]
            self.logger.debug("PACKET_OUT[data] : %s \n", recvpkt.data)

            # PACKET_OUT送信
            self.send_msg_to_packetout(msgbase.datapath, recvpkt)

        else:
            self.logger.info("dispatch[type_] = Not exist(%s) \n",
                             dispatch["type_"])
            return False

    # =========================================================================
    # get_msgbase
    # =========================================================================
    def get_msgbase(self, datapathid):
        self.logger.debug("")

        self.logger.debug("【datapathid】 : %s【dic_msg】 : %s",
                          datapathid, self.dic_msg.items())

        # CHECK DICTIONARY[msg]
        if not datapathid in self.dic_msg:
            self.logger.info("DICTIONARY[datapathid] = None \n")
            return None

        else:
            self.logger.debug("DICTIONARY[dic_msg] : %s \n",
                              self.dic_msg[datapathid])
            return self.dic_msg[datapathid]

    # =========================================================================
    # create_flow_mod
    # =========================================================================
    def create_flow_mod(self, datapath, flowdata):
        self.logger.info("")

        self.logger.debug("flowdata [datapathid] : %s", flowdata.datapathid)
        self.logger.debug("flowdata [command] : %s", flowdata.command)
        self.logger.debug("flowdata [out_port] : %s", flowdata.out_port)
        self.logger.debug("flowdata [out_group] : %s", flowdata.out_group)
        self.logger.debug("flowdata [table_id] : %s", flowdata.table_id)
        self.logger.debug("flowdata [priority] : %s", flowdata.priority)
        self.logger.debug("flowdata [match] : %s", flowdata.match)
        self.logger.debug("flowdata [instructions] : %s",
                          flowdata.instructions)

        # Create flow mod message.
        ofproto = datapath.ofproto
        flowmod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0,
                                                      flowdata.table_id,
                                                      ofproto.OFPFC_ADD, 0, 0,
                                                      flowdata.priority,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      ofproto.OFPG_ANY, 0,
                                                      flowdata.match,
                                                      flowdata.instructions)
        return flowmod

    # =========================================================================
    # send_to_mld
    # =========================================================================
    def send_to_mld(self, dispatch_):
        self.logger.debug("")

        # send of zeromq
        self.send_sock.send(cPickle.dumps(dispatch_, protocol=0))
        self.logger.info("sent 1 to mld_process.")

    # =========================================================================
    # receive_from_mld
    # =========================================================================
    def receive_from_mld(self):
        self.logger.debug("")

        while True:
            if self.SOCKET_FLG == 0:
                self.logger.debug("### EXIT LOOP")
                break
            else:
                # receive of zeromq
                recvpkt = self.recv_sock.recv()
                packet = cPickle.loads(recvpkt)
                self.analyse_receive_packet(packet)
                self.org_thread_time.sleep(1)

    # =========================================================================
    # send_msg_to_flowmod
    # =========================================================================
    def send_msg_to_flowmod(self, msgbase, flowmod):
        self.logger.debug("")

        msgbase.datapath.send_msg(flowmod)

        self.logger.info("sent 1 packet to FlowMod. ")

    # =========================================================================
    # send_msg_to_barrier_request
    # =========================================================================
    def send_msg_to_barrier_request(self, msgbase):
        self.logger.debug("")

        ofp_parser = msgbase.datapath.ofproto_parser
        barrier = ofp_parser.OFPBarrierRequest(msgbase.datapath)

        self.logger.info("sent 1 packet to BarrierRequest.")
        return msgbase.datapath.send_msg(barrier)

    # =========================================================================
    # send_msg_to_packetout
    # =========================================================================
    def send_msg_to_packetout(self, msgbase, packetout):
        self.logger.debug("")

        msgbase.datapath.send_msg(packetout)

        self.logger.info("sent 1 packet to PacketOut. ")

    # =========================================================================
    # check_exists_tmp
    # =========================================================================
    def check_exists_tmp(self, filename):
        self.logger.debug(filename)

        # ファイルの存在チェック
        if os.path.exists(filename):
            return

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
    # _switch_features_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        self.logger.debug("")

        msg = ev.msg
        datapath = ev.msg.datapath

        # CHECK Already send
        if not datapath.id in self.dic_msg:

            # set msg to Dictionary
            self.dic_msg[datapath.id] = msg

            dispatch_ = dispatch(type_=mld_const.CON_SWITCH_FEATURE,
                                    datapathid=datapath.id)

            self.send_to_mld(dispatch_)

            self.logger.debug("dispatch_[SWITCH_FEATURE] : %s \n", dispatch_)

    # =========================================================================
    # barrier_reply_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _barrier_reply_handler(self, ev):
        self.logger.debug('OFPBarrierReply received')

    # =========================================================================
    # packet_in_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.debug("")

        msg = ev.msg
        pkt = packet.Packet(msg.data)

        self.logger.debug("# PACKET_IN[data] : %s \n", str(pkt))

        # CHECK ETH
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            self.logger.debug("# check ethernet : None \n")
            return False

        # CHECK VLAN
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
                                    icmpv6.ICMPV6_MEMBERSHIP_QUERY]:
            self.logger.debug("# check icmpv6.TYPE : %s \n",
                              str(pkt_icmpv6.type_))
            return False

        # CHECK FILTER_MODE
        if pkt_icmpv6.type_ in [icmpv6.MLDV2_LISTENER_REPORT]:

            for mldv2_report_group in pkt_icmpv6.data.records:

                if not mldv2_report_group.type_ \
                                        in [icmpv6.MODE_IS_INCLUDE,
                                            icmpv6.CHANGE_TO_INCLUDE_MODE,
                                            icmpv6.ALLOW_NEW_SOURCES,
                                            icmpv6.BLOCK_OLD_SOURCES]:
                    self.logger.debug("# check report_group.[type_] : %s \n",
                                      str(mldv2_report_group.type_))
                    return False

        self.logger.debug("datapath.id : %s \n",
                          str(msg.datapath.id))
        self.logger.debug("match[""in_port""] : %s \n",
                          str(msg.match["in_port"]))

        dispatch_ = dispatch(type_=mld_const.CON_PACKET_IN,
                               datapathid=msg.datapath.id,
                               cid=pkt_vlan.vid,
                               in_port=msg.match["in_port"],
                               data=pkt_icmpv6)

        self.logger.debug("dispatch_data[PACKET_IN] : %s \n", dispatch_)

        self.send_to_mld(dispatch_)
