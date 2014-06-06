from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether, inet
from ryu.lib.packet import packet as ryu_packet
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.lib import hub
hub.patch()
import time
import os
from scapy.all import *

#==========================================================================
# mld_process
#==========================================================================
class mld_process():

    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    MULTICAST_SERVICE_INFO = os.path.normpath(
        os.path.join(BASEPATH, "./multicast_service_info.csv"))
    
    # send interval(sec)
    WAIT_TIME = 5
    
    def __init__(self):
        print "in init()"
        hub.spawn(self.send_mldquey_regularly)

    #==========================================================================
    # send_mldquey_regularly
    #==========================================================================
    def send_mldquey_regularly(self):
#       TODO read file
        src = "00:11:22:33:44:55"
        dst = "33:33:00:00:00:00"
        srcip = "11::"
        dstip = "FF02::1"
        
        mc_service_info_list = []
        for line in open(self.MULTICAST_SERVICE_INFO, "r"):
            if line[0] == "#":
                continue
            else:
                # mc_addr,ip_addr
                column = list(line[:-1].split(","))
                mc_service_info_list.append(column)

        while True:
            for mc_service_info in mc_service_info_list:
                ip_addr_list = []
                ip_addr_list.append(mc_service_info[1])
                mld = self.create_mldquery(
                    mc_service_info[0], ip_addr_list)
                sendpkt = self.create_packet(src, dst, srcip, dstip, mld)
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
        return icmpv6.mldv2_report(
                    record_num=1, records=[
                        icmpv6.mldv2_report_group(type_=1, address='::')])

    #==========================================================================
    # create_packet
    #==========================================================================
    def create_packet(self, src, dst, srcip, dstip, mld):
        print "in create_packet"
        # ether
        eth = ethernet.ethernet(
#            ethertype=ether.ETH_TYPE_8021Q, dst=dst, src=src)
            ethertype=ether.ETH_TYPE_IPV6, dst=dst, src=src)
# TODO
        '''
        # vlan
        vln = vlan.vlan(vid=100, ethertype=ether.ETH_TYPE_IPV6)
        '''
        # ipv6
        ip6 = ipv6.ipv6(src=srcip, dst=dstip, nxt=inet.IPPROTO_ICMPV6)
        # mldv2
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
        print "created ryu-packet : " + str(sendpkt)

        return sendpkt

    #==========================================================================
    # send_packet
    #==========================================================================
    def send_packet(self, ryu_packet):
        sendpkt = Packet(ryu_packet.data)
#        print "### scapy Packet ###"
#        print type(sendpkt)
#        sendpkt.show()
#        sendp(sendpkt)

    #==========================================================================
    # listener_packet
    #==========================================================================
    def listener_packet(self, packet):
        ryu_pkt = ryu_packet.Packet(str(packet))
        pkt_icmpv6 = ryu_pkt.get_protocols(icmpv6.icmpv6)

        # MLDv2 Query
        if pkt_icmpv6[0].type_ == icmpv6.MLD_LISTENER_QUERY:
            print "***** MLDv2 Query : " + str(pkt_icmpv6[0].data)

        # MLDv2 Report
        if pkt_icmpv6[0].type_ == icmpv6.MLDV2_LISTENER_REPORT:
            print "***** MLDv2 Report : " + str(pkt_icmpv6[0].data)

    #==========================================================================
    # sniff
    #==========================================================================
    def sniff(self):
        sniff(prn=self.listener_packet, filter="ip6 and icmp6")

if __name__ == '__main__':
    mld_proc = mld_process()
    mld_proc.sniff()
