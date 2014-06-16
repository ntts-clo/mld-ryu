import zmq

from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether, inet
from ryu.lib.packet import packet, ethernet, ipv6, icmpv6, vlan
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls


class PacketInForwarder(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(PacketInForwarder, self).__init__(*args, **kwargs)
        ctx = zmq.Context()
        self.sock = ctx.socket(zmq.PUB)
        
        #self.sock.bind('tcp://0.0.0.0:12345')
        self.sock.bind('ipc:///tmp/feeds/')
        #self.sock.send(ev.msg.data)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print ("packet_in START")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        # get_protocols(ethernet)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        self.logger.debug('ethernet= %s ', str(pkt_eth))
        dst = pkt_eth.dst
        src = pkt_eth.src

        pkt_ipv6 = None
        pkt_icmpv6 = None
        if 'ipv6' in self.PROTPCOL:
            # get_protocols(pkt_ipv6)
            pkt_ipv6 = pkt.get_protocols(ipv6.ipv6)
            if 0 < len(pkt_ipv6):
                self.logger.debug('ipv6= %s', str(pkt_ipv6))

            # get_protocols(pkt_icmpv6)
            pkt_icmpv6 = pkt.get_protocols(icmpv6.icmpv6)
            if 0 < len(pkt_icmpv6):
                self.logger.debug(
                    'icmpv6= %s icmpv6.ND_NEIGHBOR_SOLICIT = %s',
                    str(pkt_icmpv6), icmpv6.ND_NEIGHBOR_SOLICIT)

                if pkt_icmpv6[0].type_ not in [
                        icmpv6.MLDV2_LISTENER_REPORT,
                        icmpv6.ICMPV6_MEMBERSHIP_QUERY]:
                    print "icmpv6.type is " + str(pkt_icmpv6[0].type_)
                    return

        dpid = datapath
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug(
            'packet in %s %s %s %s %s',
            dpid, src, dst, in_port, str(self.packet_in_cnt))

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        self.logger.debug(
            'in_port = %s, out_port = %s, OFPP_FLOOD = %s',
            str(in_port), str(out_port), str(ofproto.OFPP_FLOOD))

        if out_port != ofproto.OFPP_FLOOD:

            if 'eth' in self.PROTPCOL:
                # match
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                # miss match
                match = parser.OFPMatch(
                    in_port=in_port, eth_type=0, eth_dst=dst)
            elif 'ipv6' in self.PROTPCOL:
                match = parser.OFPMatch(
                    in_port=in_port, eth_type=ether.ETH_TYPE_IPV6,
                    ip_proto=inet.IPPROTO_ICMPV6, ipv6_dst=dst)

            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        """
        sendpkt = self.createPacket(
            src, dst, pkt_ipv6[0].src, pkt_ipv6[0].dst)
        self.sendPacketOut(
            parser, datapath, in_port, actions, sendpkt.data)
        """

        self.sock.send('hello')
        self.sock.send(ev.msg.data)