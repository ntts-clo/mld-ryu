import binascii
import zmq
import os
from ryu.lib import hub
hub.patch()
from zmq.eventloop import ioloop, zmqstream


class PacketInReciver():
    IPC = "ipc://"
    RECV_PATH = "/tmp/feeds/test1"
    IPC_PATH_RECV = IPC + RECV_PATH

    def __init__(self):
        self.check_exists_tmp(self.RECV_PATH)

        ctx = zmq.Context()
        self.recv_sock = ctx.socket(zmq.SUB) 
        self.recv_sock.connect(self.IPC_PATH_RECV)
        self.recv_sock.setsockopt(zmq.SUBSCRIBE, "")

        self.recv_stream = zmqstream.ZMQStream(self.recv_sock)
        self.recv_stream.on_recv(callback=self.receive)

    # =========================================================================
    # check_exists_tmp
    # =========================================================================
    def check_exists_tmp(self, filename):
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

    def receive(self, msgs):
        for msg in msgs:
            print binascii.hexlify(msg)


if __name__ == '__main__':
    pck_in_recv = PacketInReciver()
    ioloop.IOLoop.instance().start()