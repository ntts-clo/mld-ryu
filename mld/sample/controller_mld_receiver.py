import cPickle
import binascii
import zmq

IPC_PATH = "ipc:///tmp/feeds/0"

ctx = zmq.Context()
sock = ctx.socket(zmq.SUB)

sock.connect(IPC_PATH)
sock.setsockopt(zmq.SUBSCRIBE, "")

while True:
    recvpkt = sock.recv()
    data = cPickle.loads(recvpkt)
    print "### mld_receiver START"
    print data
    #print binascii.hexlify(data)
    print "### mld_receiver END"
