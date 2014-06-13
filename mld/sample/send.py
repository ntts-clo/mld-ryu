'''
$ sudo ip link add veth0 type veth peer name veth1
$ sudo ip netns add ns0
$ sudo ip link set dev veth0 netns ns0
$ sudo ip netns exec ns0 bash
# python send.py
'''
import socket
from ryu.lib.packet import packet, ethernet, vlan, ipv6, icmpv6
from ryu.ofproto import ether, inet

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sock.bind(('veth0', 0))

pkt = packet.Packet()
pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q))
pkt.add_protocol(vlan.vlan(vid=10, ethertype=ether.ETH_TYPE_IPV6))
pkt.add_protocol(ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6))
pkt.add_protocol(icmpv6.icmpv6(
    type_=icmpv6.MLD_LISTENER_QUERY,
    data=icmpv6.mldv2_query()))
pkt.serialize()

sock.send(pkt.data)