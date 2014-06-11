import binascii
import kombu
from ryu.lib.packet import packet

conn = kombu.Connection('amqp://')
conn.connect()
pktq = conn.SimpleQueue('pktq')
while True:
    msg = pktq.get()
    pkt = packet.Packet(msg.payload)
    print("Received: %s" %  pkt)
    msg.ack()