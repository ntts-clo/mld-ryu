# coding: utf-8
# create_file(zmp tmp file)
#  /tmp/feeds/0
#  /tmp/feeds/1

from ryu.ofproto import ofproto_v1_3, ether, inet
from ryu.lib.packet import packet, ethernet, ipv6, icmpv6, vlan
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


class mld_controller(simple_switch_13.SimpleSwitch13):

    LOG_LEVEL = logging.DEBUG

    # send interval(sec)
    WAIT_TIME = 1

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    IPC = "ipc://"
    SEND_PATH = "/tmp/feeds/ryu-mld"
    RECV_PATH = "/tmp/feeds/mld-ryu"
    IPC_PATH_SEND = IPC + SEND_PATH
    IPC_PATH_RECV = IPC + RECV_PATH

    org_thread = patcher.original("threading")
    org_thread_time = patcher.original("time")

    def __init__(self, *args, **kwargs):
        super(mld_controller, self).__init__(*args, **kwargs)

        stream_log = logging.StreamHandler()
        stream_log.setFormatter(logging.Formatter(
                                "%(asctime)s [%(levelname)s] - "
                                "%(threadName)s(%(funcName)s) - "
                                "%(message)s"
                                ))
        self.logger = logging.getLogger(type(self).__name__)
        self.logger.addHandler(stream_log)
        self.logger.setLevel(self.LOG_LEVEL)
        self.logger.debug("")

        patcher.monkey_patch()

        # ====================================================================
        # CRETATE SCOKET
        # ====================================================================
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

        recv_thread = self.org_thread.Thread(
                                    target=self.receive_from_mld,
                                    name="ReceiveThread")

        recv_thread.start()

    # =========================================================================
    # packet_in_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.debug("")

        msg = ev.msg
        pkt = packet.Packet(msg.data)

        # CHECK ETH
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return

        # CHECK ICMPV6
        pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
        if not pkt_icmpv6:
            return

        # CHECK MLD TYPE
        if not pkt_icmpv6.type_ in [icmpv6.MLDV2_LISTENER_REPORT,
                                    icmpv6.ICMPV6_MEMBERSHIP_QUERY]:
            return

        self.logger.debug("packet-in %s \n", (pkt))

        self.send_packet_to_mld(pkt)

    # =========================================================================
    # _switch_features_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        self.logger.debug("")

        self.msg = ev.msg
        self.datapath = ev.msg.datapath

    # =========================================================================
    # send_packet_to_mld
    # =========================================================================
    def send_packet_to_mld(self, sendpkt):
        self.logger.debug("")

        # send of zeromq
        self.send_sock.send(cPickle.dumps(sendpkt, protocol=0))
        self.logger.info("sent 1 packet to mld_process.")

    # =========================================================================
    # receive_from_mld
    # =========================================================================
    def receive_from_mld(self):
        self.logger.debug("")

        while True:
            # receive of zeromq
            recvpkt = self.recv_sock.recv()
            packet = cPickle.loads(recvpkt)
            self.logger.debug("####recvpkt= %s \n", str(packet))
            self.send_packet_out(packet)
            self.org_thread_time.sleep(self.WAIT_TIME)

    # =========================================================================
    # sendPacketOut
    # =========================================================================
    def send_packet_out(self, packet):
        self.logger.debug("")

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt_eth = packet.get_protocols(ethernet.ethernet)[0]
        dst = pkt_eth.dst
        src = pkt_eth.src
        self.mac_to_port.setdefault(datapath, {})

        self.logger.debug("packet out %s %s %s", datapath, src, dst)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=0xffffffff,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=packet.data)

        self.send_msg(datapath, out)

    # =========================================================================
    # send_msg
    # =========================================================================
    def send_msg(self, datapath, packetout):
        self.logger.debug("")

        datapath.send_msg(packetout)

        self.logger.info("sent 1 packet to PacketOut. ")

    # =========================================================================
    # check_exists_tmp
    # =========================================================================
    def check_exists_tmp(self, filename):
        self.logger.debug("")

        if os.path.exists(filename):
            return

        else:
            f = open(filename, "w")
            f.write("")
            f.close()
            self.logger.info("create file [%s]", filename)
