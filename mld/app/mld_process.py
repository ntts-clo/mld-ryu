# coding: utf-8
# zmq install
#  >sudo apt-get install libzmq-dev
#  >sudo apt-get install python-zmq

from ryu.ofproto import ether, inet
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.lib import hub
from scapy import sendrecv
from scapy import packet as scapy_packet
from eventlet import patcher
from icmpv6_extend import icmpv6_extend
import os
import logging
import logging.config
import cPickle
import zmq
hub.patch()


# ==========================================================================
# mld_process
# ==========================================================================
class mld_process():

    # send interval(sec)
    WAIT_TIME = 10

    IPC_PATH_RECV = "ipc:///tmp/feeds/0"
    IPC_PATH_SEND = "ipc:///tmp/feeds/1"
    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    MULTICAST_SERVICE_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./multicast_service_info.csv"))
    ADDRESS_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./address_info.csv"))
    addressinfo = []

    org_thread = patcher.original("threading")
    org_thread_time = patcher.original("time")

    def __init__(self):
        logging.config.fileConfig("logconf.ini")
        self.logger = logging.getLogger(__name__)
        self.logger.debug("")

        for line in open(self.ADDRESS_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                columns = list(line[:-1].split(","))
                for column in columns:
                    self.addressinfo.append(column)

        ctx = zmq.Context()
        self.recv_sock = ctx.socket(zmq.SUB)
        self.recv_sock.connect(self.IPC_PATH_RECV)
        self.recv_sock.setsockopt(zmq.SUBSCRIBE, "")

        self.send_sock = ctx.socket(zmq.PUB)
        self.send_sock.bind(self.IPC_PATH_SEND)

        self.logger.debug("addressinfo : %s", str(self.addressinfo))

    # =========================================================================
    # send_mldquey_regularly
    # =========================================================================
    def send_mldquey_regularly(self):
        self.logger.debug("")
        mc_service_info_list = []
        for line in open(self.MULTICAST_SERVICE_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                # multicast_addr, srcip_addr
                column = list(line[:-1].split(","))
                mc_service_info_list.append(column)
        self.logger.debug(
            "send address(multicast_addr, srcip_addr) : %s",
            str(mc_service_info_list))

        while True:
            for mc_service_info in mc_service_info_list:
                ip_addr_list = []
                ip_addr_list.append(mc_service_info[1])
                mld = self.create_mldquery(
                    mc_service_info[0], ip_addr_list)
                sendpkt = self.create_packet(
                    self.addressinfo[0], self.addressinfo[1],
                    self.addressinfo[2], self.addressinfo[3], mld)
                self.send_packet_to_sw(sendpkt)
                hub.sleep(self.WAIT_TIME)

    # =========================================================================
    # create_mldquery
    # =========================================================================
    def create_mldquery(self, mc_addr, ip_addr_list):
        self.logger.debug("")
        return icmpv6.mldv2_query(address=mc_addr, srcs=ip_addr_list,
                                   maxresp=10000, qqic=15)

    # =========================================================================
    # create_mldreport
    # =========================================================================
    def create_mldreport(self):
        self.logger.debug("")
        mc_service_info_list = []
        for line in open(self.MULTICAST_SERVICE_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                # mc_addr, ip_addr
                column = list(line[:-1].split(","))
                mc_service_info_list.append(column)

        for mc_service_info in mc_service_info_list:
            record_list = []

            src_list = []
            src_list.append(mc_service_info[1])

            record_list.append(icmpv6.mldv2_report_group(
                                                 type_=icmpv6.MODE_IS_INCLUDE,
                                                 num=1,
                                                 address=mc_service_info[1],
                                                 srcs=src_list))

            mld = icmpv6.mldv2_report(record_num=0,
                                      records=record_list)

            sendpkt = self.create_packet(self.addressinfo[0],
                                         self.addressinfo[1],
                                         self.addressinfo[2],
                                         self.addressinfo[3], mld)

            self.send_packet_to_ryu(sendpkt)

    # =========================================================================
    # create_packet
    # =========================================================================
    def create_packet(self, src, dst, srcip, dstip, mld):
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
        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                    data=[ipv6.option(type_=5, len_=2, data="\x00\x00"),
                          ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=srcip, dst=dstip, hop_limit=1,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

        # MLDV2
        if type(mld) == icmpv6.mldv2_query:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLD_LISTENER_QUERY, data=mld)

        elif type(mld) == icmpv6.mldv2_report:
            icmp6 = icmpv6_extend(
                type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        # ether - vlan - ipv6 - icmpv6 ( - mldv2 )
#        sendpkt = eth / vln / ip6 / icmp6
        sendpkt = eth / ip6 / icmp6
        sendpkt.serialize()
        self.logger.debug("created packet(ryu) : %s", str(sendpkt))

        return sendpkt

    # =========================================================================
    # send_packet_to_sw
    # =========================================================================
    def send_packet_to_sw(self, ryu_packet):
        self.logger.debug("")
        sendpkt = scapy_packet.Packet(ryu_packet.data)

        # send of scapy
        sendrecv.sendp(sendpkt)
        self.logger.info("sent 1 packet to switch.")

    # =========================================================================
    # send_packet_to_ryu
    # =========================================================================
    def send_packet_to_ryu(self, ryu_packet):
        self.logger.debug("")
        sendpkt = scapy_packet.Packet(ryu_packet.data)

        # send of zeromq
        self.send_sock.send(cPickle.dumps(sendpkt, protocol=0))
        self.logger.info("sent 1 packet to ryu.")

    # =========================================================================
    # listener_packet
    # =========================================================================
    def listener_packet(self, packet):
        self.logger.debug("###packet=" + str(packet))
        pkt_eth = packet.get_protocols(ethernet.ethernet)
        pkt_ipv6 = packet.get_protocols(ipv6.ipv6)
        pkt_icmpv6_list = packet.get_protocols(icmpv6.icmpv6)
        print("pkt_eth" + str(pkt_eth))
        print("pkt_ipv6" + str(pkt_ipv6))
        print("pkt_icmpv6_list" + str(pkt_icmpv6_list))
        for pkt_icmpv6 in pkt_icmpv6_list:
            # MLDv2 Query
            if pkt_icmpv6.type_ == icmpv6.MLD_LISTENER_QUERY:
                self.logger.debug("MLDv2 Query : %s",
                                  str(pkt_icmpv6.data))
                self.create_mldreport()

            # MLDv2 Report
            if pkt_icmpv6.type_ == icmpv6.MLDV2_LISTENER_REPORT:
                self.logger.debug("MLDv2 Report : %s",
                                  str(pkt_icmpv6.data))

    # =========================================================================
    # receive_from_ryu
    # =========================================================================
    def receive_from_ryu(self):
        self.logger.debug("")
        while True:
            # receive of zeromq
            recvpkt = self.recv_sock.recv()
            packet = cPickle.loads(recvpkt)
            self.logger.debug("packet : %s", str(packet))
            self.listener_packet(packet)

            self.org_thread_time.sleep(1)

if __name__ == "__main__":
    mld_proc = mld_process()
    hub.spawn(mld_proc.send_mldquey_regularly)
    recv_thre = mld_proc.org_thread.Thread(
                                target=mld_proc.receive_from_ryu,
                                name="ReceiveThread")
    recv_thre.start()
    while True:
        hub.sleep(1)
