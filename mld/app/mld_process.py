from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether, inet
from ryu.lib.packet import packet as ryu_packet
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.lib import hub
import threading
import time
from scapy.all import *

# send interval(sec)
WAIT_TIME = 10

#==========================================================================
# mld_process
#==========================================================================
class mld_process():
    def __init__(self):
# TODO
#        hub.spawn(create_mldquey_regularly)
#        '''
        query_thread = threading.Thread(target=self.create_mldquey_regularly)
        query_thread.setDaemon(True)
        query_thread.start()
        query_thread.join()
#        '''

    #==========================================================================
    # mld_process
    #==========================================================================
    def create_mldquey_regularly(self):
        src = "11:22:33:44:55:66"
        dst = "66:55:44:33:22:11"
        srcip = "11::"
        dstip = "::11"

        sendpkt = self.create_packet(src, dst, srcip, dstip,
                                icmpv6.ICMPV6_MEMBERSHIP_QUERY)

        while True:
            self.send_packet(sendpkt)
# TODO
#            hub.sleep(self.WAIT_TIME)
            time.sleep(WAIT_TIME)

    #==========================================================================
    # mld_process
    #==========================================================================
    def create_packet(self, src, dst, srcip, dstip, mldtype):
# TODO
#        create send packet
#        ether - vlan - ipv6 - icmpv6 ( - mldv2 )
        sendpkt = ryu_packet.Packet()
#        ether
        sendpkt.add_protocol(ethernet.ethernet(
#        ethertype=ether.ETH_TYPE_8021Q, dst=dst, src=src))
            ethertype=ether.ETH_TYPE_IPV6, dst=dst, src=src))
# TODO
        '''
        # vlan
        sendpkt.add_protocol(vlan.vlan(
            vid=100, ethertype=ether.ETH_TYPE_IPV6))
        '''
#        ipv6
        sendpkt.add_protocol(ipv6.ipv6(
            src=srcip, dst=dstip, nxt=inet.IPPROTO_ICMPV6))
#        mldv2
        if mldtype == icmpv6.ICMPV6_MEMBERSHIP_QUERY:
            sendpkt.add_protocol(icmpv6.icmpv6(
                type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                data=icmpv6.mldv2_query(address='::')))

        elif mldtype == icmpv6.MLDV2_LISTENER_REPORT:
            sendpkt.add_protocol(icmpv6.icmpv6(
                type_=icmpv6.MLDV2_LISTENER_REPORT,
                data=icmpv6.mldv2_report(
                    record_num=1, records=[
                        icmpv6.mldv2_report_group(type_=1, address='::')])))

        sendpkt.serialize()

        return sendpkt

    #==========================================================================
    # send_packet
    #==========================================================================
    def send_packet(self, ryu_packet):
        sendpkt = Packet(ryu_packet.data)
        print "### scapy Packet ###"
        print type(sendpkt)
        sendpkt.show()
        sendp(sendpkt)

    #==========================================================================
    # listener_packet
    #==========================================================================
    def listener_packet(self, packet):
        ryu_pkt = ryu_packet.Packet(str(packet))
        pkt_icmpv6 = ryu_pkt.get_protocols(icmpv6.icmpv6)

#        MLDv2 Query
        if pkt_icmpv6[0].type_ == icmpv6.MLD_LISTENER_QUERY:
            print "***** MLDv2 Query : " + str(pkt_icmpv6[0].data)

#        MLDv2 Report
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
