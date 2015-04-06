#!/usr/bin/env python3.4

# Copyright (c) Yuri Victorovich 2015.  All rights reserved.
# This code is licensed under BSD license.

##
## tiny-dhcp-server
##
## This is the minimalistic DHCP server implementation for FreeBSD (has some OS-specific parts)
## It responds on one specified network interface, allocates the new IP address for each server
## and assigns itself as default gateway and DNS.
##

import sys
import os
import socket
import struct
import netifaces   # from port net/py-netifaces

socket_IP_RECVIF=20

## HDCP/BOOTP format
BOOTREQUEST = 1
BOOTREPLY = 2
BOOTPFormat = '!4bIHH4s4s4s4s16s64s128s64s'
BOOTPFormatSize = struct.calcsize(BOOTPFormat)
DHCPFormat = '!4bIHH4s4s4s4s16s64s128s4s'
DHCPFormatSize = struct.calcsize(DHCPFormat)

(BOOTP_OP,BOOTP_HTYPE,BOOTP_HLEN,BOOTP_HOPS,BOOTP_XID,BOOTP_SECS,
 BOOTP_FLAGS,BOOTP_CIADDR,BOOTP_YIADDR,BOOTP_SIADDR,BOOTP_GIADDR,
 BOOTP_CHADDR,BOOTP_SNAME,BOOTP_FILE,BOOTP_VEND) = range(15)

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
#DHCP_DECLINE = 4
DHCP_ACK = 5
#DHCP_NAK = 6
#DHCP_RELEASE = 7
#DHCP_INFORM = 8
#DHCP_RENEWING = 100

DHCP_IP_MASK = 1
DHCP_IP_GATEWAY = 3
DHCP_IP_DNS = 6
DHCP_LEASE_TIME = 51
DHCP_MSG = 53
DHCP_SERVER = 54
DHCP_END = 255

##
## MAIN
##

if not os.geteuid()==0:
    sys.exit("Only root can run tiny-dhcp-server")

## commandline arguments
if len(sys.argv) != 2:
    print('Usage: '+sys.argv[0]+' <interface>')
    exit(1)
iface=sys.argv[1]

## determine server IP and mask

server_addr=netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
server_mask=netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
server_broadcast=netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['broadcast']
server = socket.inet_aton(server_addr)
mask = socket.inet_aton(server_mask)

## IP pool

ip_pool = int.from_bytes(server, 'big')+1

## create receving socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.IPPROTO_IP, socket_IP_RECVIF, 1)
sock.bind(('0.0.0.0', 67))

## read/reply loop

while True:
    ## read
    (data, flags, ancillary, addr) = sock.recvmsg(1024, 256)
    # parse out iface from flags
    for flag in flags:
        (x, fn, bb) = flag
        if fn == socket_IP_RECVIF:
            msg_iface="".join(map(chr, bb[8:8+bb[5]])) # kernel struct sockaddr_dl, fields nlen and data
    if msg_iface != iface:
        #print('discarding request from other interface '+msg_iface)
        continue # ignore other interfaces

    #print('==> Got packet: addr %s on socket %s' % (addr, sock.getsockname()))
    if len(data) < DHCPFormatSize:
        raise 'Cannot be a DHCP or BOOTP request - too small!'
    if socket.inet_aton(addr[0])==server:
        #print("Ignored invalid request")
        continue

    ## parse
    tail = data[DHCPFormatSize:]
    buf = list(struct.unpack(DHCPFormat, data[:DHCPFormatSize]))
    if buf[BOOTP_OP] != BOOTREQUEST:
        raise 'Not a BOOTREQUEST'

    ## options
    options = {}
    while tail:
        tag = tail[0]
        if tag == 0:
            continue
        if tag == 0xff:
            break
        length = tail[1]
        (value, ) = struct.unpack('!%ss' % length, tail[2:2+length])
        tail = tail[2+length:]
        options[tag] = value

    ## message type
    dhcp_msg_type = options[53][0]
    if dhcp_msg_type == DHCP_DISCOVER:
        dhcp_reply = DHCP_OFFER
    elif dhcp_msg_type == DHCP_REQUEST:
        dhcp_reply = DHCP_ACK
    else:
        print ("Unknown DHCP message type %d" % dhcp_msg_type)
        exit(1)

    ## allocate IP

    #print('client says he has IP '+ str(buf[BOOTP_CIADDR]))
    if buf[BOOTP_CIADDR] == b'\x00\x00\x00\x00':
        buf[BOOTP_YIADDR] = struct.pack('>I', ip_pool)
        buf[BOOTP_SECS] = 0
        buf[BOOTP_FLAGS] = 0
        ip_pool = ip_pool + 1
        #print('allocating IP '+ str(buf[BOOTP_YIADDR]))
    else:
        buf[BOOTP_YIADDR] = buf[BOOTP_CIADDR]
        #print('already IP '+ str(buf[BOOTP_YIADDR]))
    buf[BOOTP_SIADDR] = buf[BOOTP_GIADDR] = server

    ## reply

    buf[BOOTP_OP] = BOOTREPLY
    pkt = struct.pack(DHCPFormat, *buf)
    pkt += struct.pack('!BBB',  DHCP_MSG,        1, dhcp_reply)
    pkt += struct.pack('!BB4s', DHCP_SERVER,     4, server)
    pkt += struct.pack('!BB4s', DHCP_IP_MASK,    4, mask)
    pkt += struct.pack('!BB4s', DHCP_IP_GATEWAY, 4, server)
    pkt += struct.pack('!BB4s', DHCP_IP_DNS,     4, server)
    pkt += struct.pack('!BBI',  DHCP_LEASE_TIME, 4, int(365*3600))
    pkt += struct.pack('!BB',   DHCP_END,        0)
    sock.sendto(pkt, (server_broadcast, 68))
    #print('<== Sent response')
