'''
$ sudo ip netns add ns1
$ sudo ip link set dev veth1 netns ns1
$ sudo ip netns exec ns1 bash
# python recv.py
'''
import pcap
from ryu.lib.packet import packet, icmpv6

for ts, data in pcap.pcap():
	pkt = packet.Packet(data)
	i = pkt.get_protocol(icmpv6.icmpv6)
	m = i.data
	print ts, i