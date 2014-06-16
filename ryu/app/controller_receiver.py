import binascii
import zmq

ctx = zmq.Context()
sock = ctx.socket(zmq.SUB)
#sock.connect('tcp://127.0.0.1:12345')
sock.connect('ipc:///tmp/feeds/')
sock.setsockopt(zmq.SUBSCRIBE, "") # receive all data

while True:
    data = sock.recv()
    print binascii.hexlify(data)