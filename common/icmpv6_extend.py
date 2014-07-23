from ryu.ofproto import inet
from ryu.lib.packet import icmpv6, ipv6
from ryu.lib import addrconv
import struct
import array
import socket

class icmpv6_extend(icmpv6.icmpv6):
    # override
    def serialize(self, payload, prev):
        hdr = bytearray(struct.pack(
            '!BBH', self.type_, self.code, self.csum))

        if self.data is not None:
            hdr += self.data.serialize()
        if self.csum == 0:
            if prev.ext_hdrs:
                # ipv6 has extension headers
                nxt = inet.IPPROTO_ICMPV6
            else:
                nxt = prev.nxt
            self.csum = checksum_ip(
                prev, len(hdr), hdr + payload, nxt)
            struct.pack_into('!H', hdr, 2, self.csum)
        return hdr

def checksum_ip(ipvx, length, payload, nxt):
    if ipvx.version == 6:
        header = struct.pack('!16s16sI3xB',
                             addrconv.ipv6.text_to_bin(ipvx.src),
                             addrconv.ipv6.text_to_bin(ipvx.dst),
                             length, nxt)
    else:
        raise ValueError('Unknown IP version %d' % ipvx.version)

    buf = header + payload
    return checksum(buf)

def checksum(data):
    if len(data) % 2:
        data += '\x00'

    data = str(data)    # input can be bytearray.
    s = sum(array.array('H', data))
    s = (s & 0xffff) + (s >> 16)
    s += (s >> 16)
    return socket.ntohs(~s & 0xffff)
