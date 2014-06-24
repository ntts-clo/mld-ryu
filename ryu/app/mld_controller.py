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


class mld_controller(simple_switch_13.SimpleSwitch13):

    LOG_LEVEL = logging.DEBUG

    # send interval(sec)
    WAIT_TIME = 1

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    IPC_PATH_SEND = "ipc:///tmp/feeds/0"
    IPC_PATH_RECV = "ipc:///tmp/feeds/1"

    org_thread = patcher.original("threading")
    org_thread_time = patcher.original("time")
    patcher.monkey_patch()

    def __init__(self, *args, **kwargs):
        super(mld_controller, self).__init__(*args, **kwargs)

        logging.config.fileConfig("logconf.ini")
        self.logger = logging.getLogger(__name__)
        self.logger.debug("")

        # ====================================================================
        # CRETATE SCOKET
        # ====================================================================
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

# TODO
        srcip = "fe80::200:ff:fe00:1"
        dstip = "fe80::200:ff:fe00:2"
        msg = ev.msg
        pkt = packet.Packet(msg.data)

        # get_protocols(ethernet)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = pkt_eth.dst
        src = pkt_eth.src

        sendpkt = self.createPacket(src, dst, srcip, dstip)
        self.send_packet_to_mld(sendpkt)

    # =========================================================================
    # _switch_features_handler
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        self.logger.debug("")

        self.msg = ev.msg
        self.datapath = ev.msg.datapath

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
        '''
        # VLAN
        vln = vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6)
        '''
        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                    data=[ipv6.option(type_=5, len_=2, data="\x00\x00"),
                          ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=srcip, dst=dstip, hop_limit=1,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

        # MLDV2
        icmp6 = icmpv6_extend(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                            data=icmpv6.mldv2_query(address="ff38::1"))

        # ether - vlan - ipv6 - icmpv6 ( - mldv2 )
#        sendpkt = eth / vln / ip6 / icmp6
        sendpkt = eth / ip6 / icmp6
        self.logger.debug("####created packet= %s \n", str(sendpkt))
        sendpkt.serialize()

        return sendpkt

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
            self.sendPacketOut(packet)
            self.org_thread_time.sleep(self.WAIT_TIME)

    # =========================================================================
    # sendPacketOut
    # =========================================================================
    def sendPacketOut(self, packet):
        self.logger.debug("")

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

# TODO
        pkt_eth = packet.get_protocols(ethernet.ethernet)[0]
        dst = pkt_eth.dst
        src = pkt_eth.src
        in_port = 1234
        self.mac_to_port.setdefault(datapath, {})

        self.logger.debug("packet out %s %s %s %s",
                          datapath, src, dst, in_port)

        self.mac_to_port[datapath][src] = in_port

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=0xffffffff,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=packet.data)

        datapath.send_msg(out)

        self.logger.info("sent 1 packet to PacketOut. ")
