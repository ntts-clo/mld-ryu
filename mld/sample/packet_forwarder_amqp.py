import zmq
import kombu

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls


class PacketInForwarder(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(PacketInForwarder, self).__init__(*args, **kwargs)
        conn = kombu.Connection('amqp://')
        conn.connect()
        self.conn = conn

        self.pktq = conn.SimpleQueue('pktq')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.pktq.put(ev.msg.data)