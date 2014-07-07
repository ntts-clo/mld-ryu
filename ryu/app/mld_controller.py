# coding: utf-8

from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, icmpv6, vlan
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from icmpv6_extend import icmpv6_extend
import cPickle
import zmq
from eventlet import patcher
import logging
import os
os.sys.path.append("../../common")
from zmq_dispatch import dispatch
from read_json import read_json
import mld_const


class mld_controller(simple_switch_13.SimpleSwitch13):
    SOCKET_FLG = 1

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    org_thread = patcher.original("threading")
    org_thread_time = patcher.original("time")

    dic_msg = {}

    def __init__(self, *args, **kwargs):

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

        self.IPC = self.config["ipc_url"]
        self.SEND_PATH = self.config["ipc_ryu-mld"]
        self.RECV_PATH = self.config["ipc_mld-ryu"]
        self.IPC_PATH_SEND = self.IPC + self.SEND_PATH
        self.IPC_PATH_RECV = self.IPC + self.RECV_PATH

        # システムモジュールのソケットに対しパッチを適用
        patcher.monkey_patch()

        # ソケット生成
        self.cretate_scoket()

        # ReceiveThread
        recv_thread = self.org_thread.Thread(
                                    target=self.receive_from_mld,
                                    name="ReceiveThread")
        recv_thread.start()

    # =========================================================================
    # CRETATE SCOKET
    # =========================================================================
    def cretate_scoket(self):
        # CHECK TMP FILE(SEND)
        self.check_exists_tmp(self.SEND_PATH)

        # CHECK TMP FILE(RECV)
        self.check_exists_tmp(self.RECV_PATH)

        ctx = zmq.Context()
        # SEND SOCKET CREATE
        self.send_sock = ctx.socket(zmq.PUB)
        self.send_sock.bind(self.IPC_PATH_SEND)
        self.logger.debug("[SendSocket]IPC %s", self.IPC_PATH_SEND)

        # RECV SOCKET CREATE
        self.recv_sock = ctx.socket(zmq.SUB) 
        self.recv_sock.connect(self.IPC_PATH_RECV)
        self.recv_sock.setsockopt(zmq.SUBSCRIBE, "")
        self.logger.debug("[RecvSocket]IPC %s", self.IPC_PATH_RECV)

    # ==================================================================
    # analyse_receive_packet
    # ==================================================================
    def analyse_receive_packet(self, recvpkt):
        self.logger.debug("")
        dispatch = recvpkt.dispatch
        self.logger.debug("ryu received dispatch : %s \n", str(dispatch))

        datapathid = dispatch["datapathid"]

        items = self.dic_msg.items()
        self.logger.debug("【dic_msg】 %s", items)

        # CHECK DICTIONARY[msg]
        if not datapathid in self.dic_msg:
            self.logger.info("DICTIONARY[datapathid] = None \n")
            return
        else:
            self.msgbase = self.dic_msg[datapathid]
            self.logger.debug("DICTIONARY[dic_msg] : %s \n", self.msgbase)

            # CHECK dispatch[type_]
            if dispatch["type_"] == mld_const.CON_FLOW_MOD:

                flowmodlist = dispatch["data"]
                self.logger.debug("FLOW_MOD[data] : %s \n", dispatch["data"])

                for flowmod in flowmodlist:
                    # FLOW_MOD送信
                    self.logger.debug("FLOW_MOD[buffer_id] : %s \n",
                                      flowmod.buffer_id)
                    self.send_msg_to_flowmod(self.msgbase, flowmod)
                    # BARRIER_REQUEST送信
                    self.send_msg_to_barrier_request(self.msgbase)

            elif dispatch["type_"] == mld_const.CON_PACKET_OUT:
                recvpkt = dispatch["data"]
                self.logger.debug("PACKET_OUT[data] : %s \n", recvpkt.data)
                # PACKET_OUT送信
                self.send_msg_to_packetout(self.msgbase, recvpkt)

            else:
                self.logger.info("dispatch[type_] = Not exist(%s) \n",
                                 dispatch["type_"])
                return

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

        msgbase.datapath.send(flowmod)

        self.logger.info("sent 1 packet to FlowMod. ")

    # =========================================================================
    # send_msg_to_flowmod
    # =========================================================================
    def send_msg_to_barrier_request(self, msgbase):
        self.logger.debug("")

        datapath = msgbase.datapath
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPBarrierRequest(datapath)
        datapath.send(req)

        self.logger.info("sent 1 packet to BarrierRequest. ")

    # =========================================================================
    # send_msg_to_packetout
    # =========================================================================
    def send_msg_to_packetout(self, msgbase, packetout):
        self.logger.debug("")

        msgbase.datapath.send(packetout)

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

            self.logger.debug("dispatch_[SWITCH_FEATURE] : %s \n", dispatch_)

    # =========================================================================
    # barrier_reply_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _barrier_reply_handler(self, ev):
        self.logger.debug("")

    # =========================================================================
    # packet_in_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.debug("")
        #self.loop.start()
        msg = ev.msg
        pkt = packet.Packet(msg.data)

        self.logger.debug("# PACKET_IN[data] : %s \n", str(pkt))

        # CHECK ETH
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            self.logger.debug("# check ethernet : None \n")
            return

        # CHECK VLAN
        pkt_vlan = pkt.get_protocol(vlan.vlan)
        if not pkt_vlan:
            self.logger.debug("# check vlan : None \n")

        # CHECK ICMPV6
        pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
        if not pkt_icmpv6:
            self.logger.debug("# check icmpv6 : None \n")
            return

        # CHECK MLD TYPE
        if not pkt_icmpv6.type_ in [icmpv6.MLDV2_LISTENER_REPORT,
                                    icmpv6.ICMPV6_MEMBERSHIP_QUERY]:
            self.logger.debug("# check icmpv6.TYPE : %s \n",
                              str(pkt_icmpv6.type_))
            return

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
                    return

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

