#!/usr/local/bin/python3.4

# Copyright (C) 2015 by Yuri Victorovich. All rights reserved.
# This code is licensed under BSD license.

##
## tiny-udp-anti-nat
##
## This is the UDP packet filter that changes the destination ip and port of USB
## packets in both directions. It gets UDP packets from the divert socket
## provided by the firewall rules.
##

## Sample divert ipfw rules
#$ipfw 03055 divert 03056 log udp from 1.1.1.2 to any in via tap1
#$ipfw 03056 divert 03056 log udp from 1.1.1.1 to any out via tap1
#$ipfw 03057 allow log udp from 1.1.1.0/24 to 1.1.1.1 in via tap1
#$ipfw 03058 allow log udp from 1.1.1.1 to 1.1.1.0/24 out via tap1


import socket
import struct
import net_checksums

# arguments
arg_clnt_divert_ip = "1.1.1.1"
arg_clnt_divert_port = 3056
arg_port_old = 53
arg_port_new = 10053

# missing constants
socket_IPPROTO_DIVERT=258

##
## procedures
##

def unpack_port(pkt, off):
    return socket.ntohs(struct.unpack('H', pkt[off:off+2])[0])

def pack_port(pkt, off, port):
    pkt[off:off+2] = struct.pack('H', socket.htons(port))

def create_sock_divert(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_IPPROTO_DIVERT)
    sock.bind((ip, port))
    return sock

##
## MAIN cycle
##

sock = create_sock_divert(arg_clnt_divert_ip, arg_clnt_divert_port)

# main event loop
while True:
    (pkt, addr) = sock.recvfrom(64000, 1024)
    pkt = bytearray(pkt)
    print('received addr=%s' % (str(addr)))
    # process
    pkt_port_src = unpack_port(pkt, 20)
    pkt_port_dst = unpack_port(pkt, 22)
    if pkt_port_dst == arg_port_old:
        print('replacing OLD->NEW')
        pack_port(pkt, 22, arg_port_new)
    elif pkt_port_src == arg_port_new:
        print('replacing NEW->OLD')
        pack_port(pkt, 20, arg_port_old)
    else:
        print('unknown packet received: port=%d' % (pkt_port_dst))
    # recompute checksum
    net_checksums.checksum_calc_udp_packet(pkt)
    # send further
    sock.sendto(pkt, addr)

