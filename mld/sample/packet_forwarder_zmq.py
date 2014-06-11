import zmq

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls


class PacketInForwarder(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(PacketInForwarder, self).__init__(*args, **kwargs)
        ctx = zmq.Context()
        self.sock = ctx.socket(zmq.PUB)
        self.sock.bind('tcp://0.0.0.0:12345')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.sock.send(ev.msg.data)