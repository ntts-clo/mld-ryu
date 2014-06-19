# coding: utf-8
# zmq install
#  >sudo apt-get install libzmq-dev
#

from ryu.ofproto import ether, inet
from ryu.lib.packet import packet as ryu_packet
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.lib import hub
hub.patch()
from scapy import sendrecv
from scapy import packet as scapy_packet
from icmpv6_extend import icmpv6_extend
import os
import logging
import cPickle
import zmq


# ==========================================================================
# mld_process
# ==========================================================================
class mld_process():

    LOG_LEVEL = logging.DEBUG
    
    # send interval(sec)
    WAIT_TIME = 10

    IPC_PATH = "ipc:///tmp/feeds/0"
    IPC_PATH_SEND = "ipc:///tmp/feeds/1"
    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    MULTICAST_SERVICE_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./multicast_service_info.csv"))
    ADDRESS_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./address_info.csv"))
    addressinfo = []

    ctx = zmq.Context()
    sock = ctx.socket(zmq.SUB)
    sock.connect(IPC_PATH)
    sock.setsockopt(zmq.SUBSCRIBE, "")

    sendsock = ctx.socket(zmq.PUB)
    sendsock.bind(IPC_PATH_SEND)

    def __init__(self):
        stream_log = logging.StreamHandler()
        stream_log.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] %(funcName)s %(message)s'))
        self.logger = logging.getLogger(type(self).__name__)
        self.logger.addHandler(stream_log)
        self.logger.setLevel(self.LOG_LEVEL)
        self.logger.debug("")

        for line in open(self.ADDRESS_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                columns = list(line[:-1].split(","))
                for column in columns:
                    self.addressinfo.append(column)

        self.logger.debug("addressinfo : %s" , str(self.addressinfo))
        hub.spawn(self.send_mldquey_regularly)

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
        '''
        # VLAN
        vln = vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6)
        '''
        # IPV6 with Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                            data=[ipv6.option(type_=5, len_=2, data=""),
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
        self.sendsock.send(cPickle.dumps(sendpkt, protocol=0))
        self.logger.info("sent 1 packet to ryu.")

    # =========================================================================
    # listener_packet
    # =========================================================================
    def listener_packet(self, packet):
        self.logger.debug("")
        ryu_pkt = ryu_packet.Packet(str(packet))
        pkt_icmpv6_list = ryu_pkt.get_protocols(icmpv6.icmpv6)

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
    # sniff
    # =========================================================================
    def sniff(self):
        self.logger.debug("")
        sendrecv.sniff(prn=self.listener_packet,
                       filter='ip6 proto 0 and multicast')

if __name__ == '__main__':
    mld_proc = mld_process()
    """ comment
    # receive of sniff
    mld_proc.sniff()
    """
    while True:
        # receive of zeromq
        recvpkt = mld_proc.sock.recv()
        packet = cPickle.loads(recvpkt)
        mld_proc.listener_packet(packet)

        hub.sleep(1)

