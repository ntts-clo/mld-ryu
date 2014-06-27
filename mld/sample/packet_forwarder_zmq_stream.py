import zmq
import os
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls


class PacketInForwarder(simple_switch_13.SimpleSwitch13):

    IPC = "ipc://"
    SEND_PATH = "/tmp/feeds/test1"
    #RECV_PATH = "/tmp/feeds/test2"
    IPC_PATH_SEND = IPC + SEND_PATH
    #IPC_PATH_RECV = IPC + RECV_PATH

    def __init__(self, *args, **kwargs):
        super(PacketInForwarder, self).__init__(*args, **kwargs)

        # CHECK TMP FILE(SEND)
        self.check_exists_tmp(self.SEND_PATH)
        # CHECK TMP FILE(RECV)
#        self.check_exists_tmp(self.RECV_PATH)

        ctx = zmq.Context()
        self.send_sock = ctx.socket(zmq.PUB)
        self.send_sock.bind(self.IPC_PATH_SEND)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.send_sock.send(ev.msg.data)
        print ("send msg.data")

    # =========================================================================
    # check_exists_tmp
    # =========================================================================
    def check_exists_tmp(self, filename):
        self.logger.debug("")

        if os.path.exists(filename):
            return

        else:
            dirpath = os.path.dirname(filename)
            if os.path.isdir(dirpath):
                f = open(filename, "w")
                f.write("")
                f.close()
                self.logger.info("create file[%s]", filename)
            else:
                os.makedirs(dirpath)
                f = open(filename, "w")
                f.write("")
                f.close()
                self.logger.info("create dir[%s], file[%s]",
                                 dirpath, filename)
