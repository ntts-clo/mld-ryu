import binascii
import zmq

IPC_PATH = "ipc:///tmp/feeds/0"

ctx = zmq.Context()
sock = ctx.socket(zmq.SUB)

sock.connect(IPC_PATH)
sock.setsockopt(zmq.SUBSCRIBE, "") # receive all data

while True:
    data = sock.recv()
    print "### mld_receiver START"
    print binascii.hexlify(data)
    print "### mld_receiver END"
