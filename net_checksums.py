import socket
import struct
import array

def is_big_endian():
    return struct.pack("H",1) == "\x00\x01"

# Checksums are specified in rfc#768
if is_big_endian():
    def checksum(pkt):
        adj=False
        if len(pkt) % 2 == 1:
            pkt += bytearray([0])
            adj=True
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        if adj:
            pkt[len(pkt)-1:] = b''
        return s & 0xffff
else:
    def checksum(pkt):
        adj=False
        if len(pkt) % 2 == 1:
            pkt += bytearray([0])
            adj=True
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        if adj:
            pkt[len(pkt)-1:] = b''
        return (((s>>8)&0xff)|s<<8) & 0xffff

def packet_new_udp_headers_for_cksum(pkt):
    header = bytearray(struct.pack("!4s4sBBH",
                 pkt[12:16],
                 pkt[16:20],
                 0,
                 socket.IPPROTO_UDP,
                 len(pkt)-20))
    return header+pkt[20:]

def checksum_calc_udp_packet(pkt):
    pkt[26:28] = bytearray(struct.pack("H", 0))
    pkt[26:28] = bytearray(struct.pack("H", socket.htons(checksum(packet_new_udp_headers_for_cksum(pkt)))))
    
