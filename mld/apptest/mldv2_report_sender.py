# coding: utf-8

# --インストール
# mld@vlc1:~$ unzip mld-ryu.zip
# mld@vlc1:~$ cd ./mld-ryu/mld/apptest
# --3000ユーザ追加
# mld@vlc1:~/mld-ryu/mld/apptest$ sudo python mldv2_report_sender.py add
# --3000ユーザ削除
# mld@vlc1:~/mld-ryu/mld/apptest$ sudo python mldv2_report_sender.py del

import os
from ryu.lib.packet import icmpv6, vlan, ipv6, ethernet
from ryu.ofproto import ether, inet
from scapy import sendrecv
from scapy import packet as scapy_packet
import sys

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
COMMON_PATH = DIR_PATH + "/../../common/"
sys.path.append(COMMON_PATH)
from icmpv6_extend import icmpv6_extend

IFACE = "eth1"
MACADDRESS = "40:a8:f0:75:6c:95"
LINKLOCALADDRESS = "fe80::42a8:f0ff:fe75:6c95"
ADDRESS_INFO = [MACADDRESS, LINKLOCALADDRESS]

SERV_IP = "2001:1::20"
MC_ADDRESS = "ff38::1:1"


class mldv2_report_sender(object):

    def __init__(self):
        pass

    # ==================================================================
    # send_add
    # ==================================================================
    def send_add(self, num_of=3000):

        record_list = []
        for report_type in (icmpv6.ALLOW_NEW_SOURCES, icmpv6.CHANGE_TO_INCLUDE_MODE):
            record_list.append(icmpv6.mldv2_report_group(type_=report_type,
                                                         address=MC_ADDRESS,
                                                         srcs=[SERV_IP]))
        mld_report = icmpv6.mldv2_report(records=record_list)

        for vid in range(num_of):
            ryu_packet = self.create_packet(ADDRESS_INFO,
                                            vid + 1,
                                            mld_report)
            scapypkt = scapy_packet.Packet(ryu_packet.data)
            sendrecv.sendp(scapypkt, iface=IFACE, verbose=0)

    # ==================================================================
    # send_del
    # ==================================================================
    def send_del(self, num_of=3000):

        record_list = []
        for report_type in (icmpv6.BLOCK_OLD_SOURCES):
            record_list.append(icmpv6.mldv2_report_group(type_=report_type,
                                                         address=MC_ADDRESS,
                                                         srcs=[SERV_IP]))
        mld_report = icmpv6.mldv2_report(records=record_list)

        for vid in range(num_of):
            ryu_packet = self.create_packet(ADDRESS_INFO,
                                            vid + 1,
                                            mld_report)
            scapypkt = scapy_packet.Packet(ryu_packet.data)
            sendrecv.sendp(scapypkt, iface=IFACE, verbose=0)

    # ==================================================================
    # create_packet
    # ==================================================================
    def create_packet(self, addressinfo, vid, mld):
        self.logger.debug("")

        # VLAN
        vln = vlan.vlan(vid=vid, ethertype=ether.ETH_TYPE_IPV6)

        # Hop-By-Hop
        ext_headers = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6, data=[
            ipv6.option(type_=5, len_=2, data="\x00\x00"),
            ipv6.option(type_=1, len_=0)])]

        # ETHER
        eth = ethernet.ethernet(
            ethertype=ether.ETH_TYPE_8021Q,
            src=addressinfo[0], dst="33:33:00:00:00:16")

        # IPV6 with ExtensionHeader
        ip6 = ipv6.ipv6(
            src=addressinfo[1], dst="ff02::16",
            hop_limit=1, nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=ext_headers)

        # MLD Report
        icmp6 = icmpv6_extend(
            type_=icmpv6.MLDV2_LISTENER_REPORT, data=mld)

        # ether - vlan - ipv6 - icmpv6 ( - mldv2 )
        sendpkt = eth / vln / ip6 / icmp6
        sendpkt.serialize()

        return sendpkt


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] in ("add", "del"):
        print "python mldv2_report_sender.py [add|del]"
        return
    elif sys.argv[1] == "add":
        mldv2_report_sender().send_add()
    elif sys.argv[1] == "del":
        mldv2_report_sender().send_del()
    return
