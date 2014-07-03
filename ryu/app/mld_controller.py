# coding: utf-8
# create_file(zmp tmp file)
#  /tmp/feeds/0
#  /tmp/feeds/1

from ryu.ofproto import ofproto_v1_3, ether, inet
from ryu.lib.packet import packet, ethernet, ipv6, icmpv6, vlan
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller import controller
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from icmpv6_extend import icmpv6_extend
import cPickle
import zmq
#TODO
from zmq.eventloop import ioloop, zmqstream
from eventlet import patcher
import logging
import os
os.sys.path.append("../../common")
from message import message
import mld_const


class mld_controller(simple_switch_13.SimpleSwitch13):

    LOG_LEVEL = logging.DEBUG

    # send interval(sec)
    WAIT_TIME = 1
    SOCKET_TIME_OUT = 1000
    SOCKET_FLG = 1
    PACKET_CHECK_FLG = "OFF" #"ON"/"OFF"

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    IPC = "ipc://"
    SEND_PATH = "/tmp/feeds/ryu-mld"
    RECV_PATH = "/tmp/feeds/mld-ryu"
#    RECV_PATH = "/tmp/feeds/test1"
    IPC_PATH_SEND = IPC + SEND_PATH
    IPC_PATH_RECV = IPC + RECV_PATH

    org_thread = patcher.original("threading")
    org_thread_time = patcher.original("time")

    loop = ioloop.IOLoop.instance()

    dic_message = {}

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
        """
        # ZMQStream
        self.recv_stream = zmqstream.ZMQStream(self.recv_sock)
        self.recv_stream.on_recv(callback=self.receive_from_mld)
        ioloop.IOLoop.instance().start()
        self.loop.add_handler(self.recv_sock, self.backend_handler, zmq.POLLIN)
        """

        # ReceiveThread
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
        #self.loop.start()
        msg = ev.msg
        pkt = packet.Packet(msg.data)

        ### DEBUG
        srcip = "fe80::200:ff:fe00:1"
        dstip = "fe80::200:ff:fe00:2"
        ### DEBUG
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = pkt_eth.dst
        src = pkt_eth.src
        pkt = self.createPacket(src, dst, srcip, dstip)

        # CHECK ETH
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if self.PACKET_CHECK_FLG == "ON" and not pkt_ethernet:
            self.logger.debug("### check ethernet = %s \n", str(pkt))
            return

        # CHECK ICMPV6
        pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
        if self.PACKET_CHECK_FLG == "ON" and not pkt_icmpv6:
            self.logger.debug("### check icmpv6 = %s \n", str(pkt))
            return

        # CHECK MLD TYPE
        if self.PACKET_CHECK_FLG == "ON" and not pkt_icmpv6.type_ in [
                                             icmpv6.MLDV2_LISTENER_REPORT,
                                             icmpv6.ICMPV6_MEMBERSHIP_QUERY]:
            self.logger.debug("### check icmpv6.TYPE = %s \n", str(pkt))
            return

        self.logger.debug("msg.datapath.id = %s \n",
                          str(msg.datapath.id))
        self.logger.debug("msg.match[""in_port""] = %s \n",
                          str(msg.match["in_port"]))

        send_message = message(type_=mld_const.CON_PACKET_IN,
                               datapath=msg.datapath.id,
                               in_port=msg.match["in_port"],
                               data=pkt_icmpv6)

        self.logger.debug("send message[PACKET_IN] = %s \n", send_message)

        self.send_to_mld(send_message)

    # =========================================================================
    # _switch_features_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        self.logger.debug("")

        msg = ev.msg
        datapath = ev.msg.datapath
        # set msg to Dictionary
        self.dic_message[datapath.id] = msg

        send_message = message(type_=mld_const.CON_SWITCH_FEATURE,
                               datapath=datapath.id)

        self.logger.debug("send message[SWITCH_FEATURE] = %s \n", send_message)
        self.send_to_mld(send_message)

    # =========================================================================
    # send_to_mld
    # =========================================================================
    def send_to_mld(self, sendpkt):
        self.logger.debug("")

        # send of zeromq
        self.send_sock.send(cPickle.dumps(sendpkt, protocol=0))
        self.logger.info("sent 1 to mld_process.")

    # =========================================================================
    # receive_from_mld
    # =========================================================================
#TODO
    """
    def receive_from_mld(self, msgs):
        self.logger.debug("")
        for msg in msgs:
            packet = msg
            #packet = cPickle.loads(msg)
            self.logger.debug("### recv packet= %s \n", str(packet))
            self.analyse_receive_packet(packet)
    """
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
                self.org_thread_time.sleep(self.WAIT_TIME)

    # ==================================================================
    # analyse_receive_packet
    # ==================================================================
    def analyse_receive_packet(self, recvpkt):
        self.logger.debug("")
        message = recvpkt.message
        self.logger.debug("###ryu received message = %s \n", str(message))

        #### DEBUG
        messagebase = None
        datapath = None
        datapathid = 1
        #### DEBUG

        # CHECK DICTIONARY[message]
        items = self.dic_message.items()
        self.logger.debug("【dic_message】 %s", items)

        if 0 < len(self.dic_message) and datapathid in self.dic_message:
            datapath = self.dic_message[datapathid]
            self.logger.debug("DICTIONARY[dic_message] = %s \n", datapath)
            messagebase = self.dic_message[datapathid]
        else:
            self.logger.debug("DICTIONARY[datapath] = None \n")
            return

        if message["type_"] == mld_const.CON_FLOW_MOD:
            flowmod = message["data"]
            self.logger.debug("FLOW_MOD[data] = %s \n", flowmod)
            self.send_msg_to_flowmod(messagebase, flowmod)

        elif message["type_"] == mld_const.CON_PACKET_OUT:
            recvpkt = message["data"]
            self.logger.debug("PACKET_OUT[data] = %s \n", recvpkt.data)
            self.send_msg_to_packetout(messagebase, recvpkt)

        else:
            self.logger.info("message[type_] = Not exist(%s) \n",
                             message["type_"])
            return

    # =========================================================================
    # send_msg_to_flowmod
    # =========================================================================
    def send_msg_to_flowmod(self, messagebase, flowmod):
        self.logger.debug("")
        messagebase.datapath.send(flowmod)
        self.logger.info("sent 1 packet to FlowMod. ")

    # =========================================================================
    # send_msg_to_packetout
    # =========================================================================
    def send_msg_to_packetout(self, messagebase, packetout):
        self.logger.debug("")
        messagebase.datapath.send(packetout)
        self.logger.info("sent 1 packet to PacketOut. ")

    # =========================================================================
    # createPacket
    # =========================================================================
    def createPacket(self, src, dst, srcip, dstip):
        self.logger.debug("")

        # ETHER
        eth = ethernet.ethernet(
#            ethertype=ether.ETH_TYPE_8021Q, dst=dst, src=src)
            ethertype=ether.ETH_TYPE_IPV6, dst=dst, src=src)

# TODO
        """
        # VLAN
        vln = vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6)
        """
        # IPV6 with HopByHop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                    data=[ipv6.option(type_=5, len_=2, data="\x00\x00"),
                          ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=srcip, dst=dstip, hop_limit=1,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

        # MLDV2
        icmp6 = icmpv6_extend(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                            data=icmpv6.mldv2_query(address="ff38::1"))

        # ether  vlan  ipv6  icmpv6(mldv2)
#        sendpkt = eth / vln / ip6 / icmp6
        sendpkt = eth / ip6 / icmp6
        self.logger.debug("### created packet= %s \n", str(sendpkt))

        sendpkt.serialize()

        return sendpkt

    # =========================================================================
    # check_exists_tmp
    # =========================================================================
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

    """
    def backend_handler(self, sock, events):
        self.logger.debug("#####")
        message = sock.recv()
        self.logger.debug("#### backend_handler : " + str(message))
    """
