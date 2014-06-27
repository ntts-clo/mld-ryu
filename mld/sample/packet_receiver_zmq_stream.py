import binascii
import zmq
import os
from eventlet import patcher
from ryu.lib import hub
hub.patch()
from zmq.eventloop import ioloop, zmqstream
ioloop.install()


class PacketInReciver():
    IPC = "ipc://"
    #SEND_PATH = "/tmp/feeds/test2"
    RECV_PATH = "/tmp/feeds/test1"
    #IPC_PATH_SEND = IPC + SEND_PATH
    IPC_PATH_RECV = IPC + RECV_PATH

    org_thread = patcher.original("threading")
    org_thread_time = patcher.original("time")

    def __init__(self):
        patcher.monkey_patch()
        # CHECK TMP FILE(SEND)
#        pck_in_recv.check_exists_tmp(self.SEND_PATH)
        # CHECK TMP FILE(RECV)
        self.check_exists_tmp(self.RECV_PATH)

        ctx = zmq.Context()
        self.recv_sock = ctx.socket(zmq.SUB) 
        self.recv_sock.connect(self.IPC_PATH_RECV)
        self.recv_sock.setsockopt(zmq.SUBSCRIBE, "")

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

    def receive(self):
        print ("receive" + str(self.recv_sock))

        while True:
            data = self.recv_sock.recv()
            print binascii.hexlify(data)


if __name__ == '__main__':
    pck_in_recv = PacketInReciver()
    recv_loop = ioloop.IOLoop.instance()
    pck_in_recv.recv_stream = zmqstream.ZMQStream(pck_in_recv.recv_sock, recv_loop)
    pck_in_recv.recv_stream.on_recv_stream(callback=pck_in_recv.receive())
    ioloop.IOLoop.instance().start()

#    recv_thread = pck_in_recv.org_thread.Thread(
#                                target=pck_in_recv.receive,
#                                name="ReceiveThread")
#    recv_thread.start()

    while True:
        hub.sleep(1)
