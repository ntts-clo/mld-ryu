#sudo apt-get install libzmq-dev
#copy icmpv6_extend
#  mld.app,icmpv6_extend to ryu.app.icmpv6_extend

import zmq
from ryu.ofproto import ofproto_v1_3, ether, inet
from ryu.lib.packet import packet, ethernet, ipv6, icmpv6, vlan
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from icmpv6_extend import icmpv6_extend

class PacketInForwarder(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    IPC_PATH = "ipc:///tmp/feeds/0"

    def __init__(self, *args, **kwargs):
        super(PacketInForwarder, self).__init__(*args, **kwargs)
        ctx = zmq.Context()
        self.sock = ctx.socket(zmq.PUB)

        self.sock.bind(self.IPC_PATH)
        print (self.IPC_PATH)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        srcip = "fe80::200:ff:fe00:1"
        dstip = "fe80::200:ff:fe00:2"

        msg = ev.msg
        pkt = packet.Packet(msg.data)
        print ("###packet_in START ", pkt)

        # get_protocols(ethernet)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = pkt_eth.dst
        src = pkt_eth.src

        sendpkt = self.createPacket(src, dst, srcip, dstip)

        self.sock.send(str(sendpkt))
        #self.sock.send(cPickle(sendpkt))

        print ("###packet_in END ", sendpkt)

    def createPacket(self, src, dst, srcip, dstip):
        # create send packet
        #eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q)
        eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_IPV6)
        #vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6, vid=100)
        hop = [ipv6.hop_opts(nxt=inet.IPPROTO_ICMPV6,
                            data=[ipv6.option(type_=5, len_=2, data=""),
                                  ipv6.option(type_=1, len_=0)])]
        ip6 = ipv6.ipv6(src=srcip, dst=dstip,
                        nxt=inet.IPPROTO_HOPOPTS, ext_hdrs=hop)
        mld = icmpv6_extend(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                            data=icmpv6.mldv2_query(address="ff38::1"))

        sendpkt = eth / ip6 / mld
        sendpkt.serialize()
        return sendpkt
