# coding: utf-8
from ryu.ofproto import ether, inet
from ryu.lib.packet import packet as ryu_packet
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.lib import hub; hub.patch()
from scapy import sendrecv
from scapy import packet as scapy_packet
import os

#==========================================================================
# mld_process
#==========================================================================
class mld_process():

    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    MULTICAST_SERVICE_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./multicast_service_info.csv"))
    ADDRESS_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./address_info.csv"))
    addressinfo = []

    # send interval(sec)
    WAIT_TIME = 10

    def __init__(self):
# Debug
        print "in init()"
        for line in open(self.ADDRESS_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                columns = list(line[:-1].split(","))
                for column in columns:
                    self.addressinfo.append(column)

# Debug
        print "addressinfo : " + str(self.addressinfo)
        hub.spawn(self.send_mldquey_regularly)

    #==========================================================================
    # send_mldquey_regularly
    #==========================================================================
    def send_mldquey_regularly(self):
# Debug
        print "in send_mldquey_regularly()"
        mc_service_info_list = []
        for line in open(self.MULTICAST_SERVICE_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                # multicast_addr, srcip_addr
                column = list(line[:-1].split(","))
                mc_service_info_list.append(column)

        while True:
            for mc_service_info in mc_service_info_list:
                ip_addr_list = []
                ip_addr_list.append(mc_service_info[1])
                mld = self.create_mldquery(
                    mc_service_info[0], ip_addr_list)
                sendpkt = self.create_packet(
                    self.addressinfo[0], self.addressinfo[1],
                    self.addressinfo[2], self.addressinfo[3], mld)
                self.send_packet(sendpkt)
                hub.sleep(self.WAIT_TIME)

    #==========================================================================
    # create_mldquery
    #==========================================================================
    def create_mldquery(self, mc_addr, ip_addr_list):
        return icmpv6.mldv2_query(address=mc_addr, srcs=ip_addr_list)

    #==========================================================================
    # create_mldreport
    #==========================================================================
    def create_mldreport(self):
        mc_service_info_list = []
        for line in open(self.MULTICAST_SERVICE_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                # mc_addr,ip_addr
                column = list(line[:-1].split(","))
                mc_service_info_list.append(column)

        for mc_service_info in mc_service_info_list:
            record_list = []

            src_list = []
            src_list.append(mc_service_info[1])

            record_list.append(icmpv6.mldv2_report_group(
                                                 type_=icmpv6.MODE_IS_EXCLUDE,
                                                 num=1,
                                                 address=self.addressinfo[4],
                                                 srcs=src_list))

            mld = icmpv6.mldv2_report(record_num=len(record_list),
                                      records=record_list)

            sendpkt = self.create_packet(self.addressinfo[0], self.addressinfo[1],
                                         self.addressinfo[2], self.addressinfo[3], mld)

            self.send_packet(sendpkt)

    #==========================================================================
    # create_packet
    #==========================================================================
    def create_packet(self, src, dst, srcip, dstip, mld):
# Debug
        print "in create_packet"
        # ETHER
        eth = ethernet.ethernet(
#            ethertype=ether.ETH_TYPE_8021Q, dst=dst, src=src)
            ethertype=ether.ETH_TYPE_IPV6, dst=dst, src=src)
# TODO
        '''
        # VLAN
        vln = vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6)
        '''
        # IPV6
        ip6 = ipv6.ipv6(src=srcip, dst=dstip, nxt=inet.IPPROTO_ICMPV6)
        # MLDV2
        if type(mld) == icmpv6.mldv2_query:
            icmp6 = icmpv6.icmpv6(
                type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY, data=mld)

        elif type(mld) == icmpv6.mldv2_report:
            icmp6 = icmpv6.icmpv6(
                type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        # ether - vlan - ipv6 - icmpv6 ( - mldv2 )
#        sendpkt = eth / vln / ip6 / icmp6
        sendpkt = eth / ip6 / icmp6
        sendpkt.serialize()
# Debug
        print "created ryu-packet : " + str(sendpkt)

        return sendpkt

    #==========================================================================
    # send_packet
    #==========================================================================
    def send_packet(self, ryu_packet):
        sendpkt = scapy_packet.Packet(ryu_packet.data)
# Debug
        print "### scapy Packet ###"
        sendpkt.show()
        sendrecv.sendp(sendpkt)

    #==========================================================================
    # listener_packet
    #==========================================================================
    def listener_packet(self, packet):
        ryu_pkt = ryu_packet.Packet(str(packet))
        pkt_icmpv6_list = ryu_pkt.get_protocols(icmpv6.icmpv6)

        for pkt_icmpv6 in pkt_icmpv6_list:
            # MLDv2 Query
            if pkt_icmpv6.type_ == icmpv6.MLD_LISTENER_QUERY:
# Debug
                print "***** MLDv2 Query : " + str(pkt_icmpv6.data)
                self.create_mldreport()

            # MLDv2 Report
            if pkt_icmpv6.type_ == icmpv6.MLDV2_LISTENER_REPORT:
# Debug
                print "***** MLDv2 Report : " + str(pkt_icmpv6.data)

    #==========================================================================
    # sniff
    #==========================================================================
    def sniff(self):
# Debug
        print('*****sniff START ******')
        # TODO send_mldquey_regularlyで作成したQueryを引っ掛けないように
        sendrecv.sniff(prn=self.listener_packet, filter="ip6 and icmp6")

if __name__ == '__main__':
    mld_proc = mld_process()
    mld_proc.sniff()
    while True:
        hub.sleep(1)
