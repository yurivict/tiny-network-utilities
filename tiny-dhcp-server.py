#!/usr/local/bin/python3.4

# Copyright (C) 2015 by Yuri Victorovich. All rights reserved.
# This code is licensed under BSD license.

##
## tiny-dhcp-server
##
## This is the minimalistic DHCP server implementation for FreeBSD (has some OS-specific parts)
## It responds on one specified network interface, allocates the new IP address for each server
## and assigns itself as default gateway and DNS.
##
## NOTE FreeBSD doesn't allow multiple DHCP listening sockets, so only one
##      instance of this program can run at a time, and it handles all
##      needed interfaces. It probably can't be combined with another DHCP server.
##

import sys, os, getopt
import socket
import struct
import codecs
import datetime
import netifaces   # from port net/py-netifaces
import tiny_utils as tu

socket_IP_RECVIF=20 # missing in python3.4

##
## Command line arguments and usage
##

arg_log_file=None
arg_pid_file=None
arg_daemonize=False
arg_unprivileged=False

def usage():
    print('%s {-l <log-file>} {-p <pid-file>} {-d} {-u} iface1 {iface2 {...}}' % (sys.argv[0]))
    sys.exit(2)

try:
    opts, args = getopt.getopt(sys.argv[1:], "l:p:du",["log=","pid=","daemonize","unprivileged"])
except getopt.GetoptError:
    usage()
for opt,arg in opts:
    if opt in ("-l", "--log"):
        arg_log_file=arg
    if opt in ("-p", "--pid"):
        arg_pid_file=arg
    if opt in ("-d", "--daemonize"):
        arg_daemonize=True
    if opt in ("-u", "--unprivileged"):
        arg_unprivileged=True

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
DHCP_INFORM = 8
#DHCP_RENEWING = 100

DHCP_IP_MASK = 1
DHCP_IP_GATEWAY = 3
DHCP_IP_DNS = 6
DHCP_LEASE_TIME = 51
DHCP_MSG = 53
DHCP_SERVER = 54
DHCP_END = 255

def logfile():
    return arg_log_file if arg_log_file is not None else '/var/log/tiny-dhcp-server.log'
def tm():
    return datetime.datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
def log(s):
    if arg_daemonize:
        with open(logfile(), "a") as myfile:
            myfile.write('%s %s\n' % (tm(), s))
    else:
        print('%s %s' % (tm(), s))
def log_discard(what):
    if arg_daemonize:
        with open(logfile(), "a") as myfile:
            myfile.write('%s discarded %s\n' % (tm(), what))
    else:
        sys.stderr.write('%s discarded %s\n' % (tm(), what))

##
## MAIN
##

if not os.geteuid()==0:
    sys.exit("Only root can run tiny-dhcp-server")

## command line arguments
if len(sys.argv) < 2:
    sys.exit('Usage: '+sys.argv[0]+' <interface1> {, <interface2> ...}')

log('starting')

## signals
tu.handle_signals(lambda msg: log(msg))

## initialize structure per iface
ifaces = {}
for iface in args:
    ifaces[iface] = {}

## determine server IP and netmask

for iface,s in ifaces.items():
    s['server']           = socket.inet_aton(netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr'])
    s['server_broadcast'] = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['broadcast']
    s['netmask']          = socket.inet_aton(netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask'])
    s['ip_pool']          = int.from_bytes(s['server'], 'big')+1
    s['mac_to_ip']        = {}

## create receving socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.IPPROTO_IP, socket_IP_RECVIF, 1)
sock.bind(('0.0.0.0', 67))

## daemonize
if arg_daemonize:
    tu.do_daemonize()

## pid file
if arg_pid_file is not None:
    tu.write_pid_file(arg_pid_file)

## lose privileges if requested
if arg_unprivileged:
    tu.drop_privileges([logfile()])

## read/reply loop

while True:
    ## read
    (data, flags, ancillary, addr) = sock.recvmsg(1024, 256)
    # parse out iface from flags
    for flag in flags:
        (x, fn, bb) = flag
        if fn == socket_IP_RECVIF:
            msg_iface="".join(map(chr, bb[8:8+bb[5]])) # kernel struct sockaddr_dl, fields nlen and data
    if msg_iface in ifaces:
        s = ifaces[msg_iface]
    else:
        log_discard('request from host %s on socket %s via an unknown interface %s' % (addr, sock.getsockname(), msg_iface))
        continue # ignore other interfaces

    log('==> got packet: addr %s on socket %s via interface %s' % (addr, sock.getsockname(), msg_iface))
    if len(data) < DHCPFormatSize:
        log_discard('too small request of size='+len(data)+' from host %s on socket %s via interface %s' % (addr, sock.getsockname(), msg_iface))
        continue
    if socket.inet_aton(addr[0]) == s['server']:
        log_discard('invalid request from host %s on socket %s via interface %s' % (addr, sock.getsockname(), msg_iface))
        continue

    ## parse
    tail = data[DHCPFormatSize:]
    buf = list(struct.unpack(DHCPFormat, data[:DHCPFormatSize]))
    if buf[BOOTP_OP] != BOOTREQUEST:
        log_discard('packet which is not a BOOTREQUEST (op=%d)' % (buf[BOOTP_OP]))
        continue

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
    elif dhcp_msg_type == DHCP_INFORM:
        log_discard('discarding DHCP INFORM message from host %s on socket %s via interface %s' % (addr, sock.getsockname(), msg_iface))
        continue # Windows sends INFORM requests to learn NetBIOS, Domain Server, Domain Name, etc, discard these
    else:
        log_discard('discarding unknown DHCP message type %d from host %s on socket %s via interface %s' % (dhcp_msg_type, addr, sock.getsockname(), msg_iface))
        continue

    ## allocate IP

    # buf[BOOTP_CIADDR] has client's previous address, but we go strictly by MAC address buf[BOOTP_CHADDR]
    log('client says he has MAC = ' + codecs.getencoder('hex')(buf[BOOTP_CHADDR])[0].decode("utf-8"))
    mac = codecs.getencoder('hex')(buf[BOOTP_CHADDR])[0].decode("utf-8")
    if mac in s['mac_to_ip']:
        buf[BOOTP_YIADDR] = s['mac_to_ip'][mac]
        log('client already has IP '+ socket.inet_ntoa(buf[BOOTP_YIADDR]))
    else:
        buf[BOOTP_YIADDR] = struct.pack('>I', s['ip_pool'])
        buf[BOOTP_SECS] = 0
        buf[BOOTP_FLAGS] = 0
        s['mac_to_ip'][mac] = buf[BOOTP_YIADDR]
        s['ip_pool'] = s['ip_pool'] + 1
        log('allocating IP '+ socket.inet_ntoa(buf[BOOTP_YIADDR]))
    buf[BOOTP_SIADDR] = buf[BOOTP_GIADDR] = s['server']

    ## reply

    buf[BOOTP_OP] = BOOTREPLY
    pkt = struct.pack(DHCPFormat, *buf)
    pkt += struct.pack('!BBB',  DHCP_MSG,        1, dhcp_reply)
    pkt += struct.pack('!BB4s', DHCP_SERVER,     4, s['server'])
    pkt += struct.pack('!BB4s', DHCP_IP_MASK,    4, s['netmask'])
    pkt += struct.pack('!BB4s', DHCP_IP_GATEWAY, 4, s['server'])
    pkt += struct.pack('!BB4s', DHCP_IP_DNS,     4, s['server'])
    pkt += struct.pack('!BBI',  DHCP_LEASE_TIME, 4, int(365*3600))
    pkt += struct.pack('!BB',   DHCP_END,        0)
    sock.sendto(pkt, (s['server_broadcast'], 68))
    log('<== sent response')
