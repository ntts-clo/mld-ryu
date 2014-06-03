from scapy.all import *
from ryu.lib.packet import *
from ryu.ofproto import ether

eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q)
vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6)
ip6 = ipv6.ipv6(dst="::1", src="::1", nxt=58)
mld = icmpv6.icmpv6(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                    data=icmpv6.mldv2_query())

ryu_pkt = eth/vln/ip6/mld
ryu_pkt.serialize()

print "*** Ryu Packet ***"
print type(ryu_pkt)
print ryu_pkt
print type(ryu_pkt.data)
print

sendpkt = Packet(ryu_pkt.data)
print "### scapy Packet ###"
print type(sendpkt)
sendpkt.show()
print

sendp(sendpkt)
