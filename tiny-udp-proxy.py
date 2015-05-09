#!/usr/local/bin/python3.4

# Copyright (C) 2015 by Yuri Victorovich. All rights reserved.
# This code is licensed under BSD license.

##
## tiny-udp-proxy
##
## This is the minimalistic UDP proxy server implementation for FreeBSD (has some OS-specific parts)
## It can listen to UDP on some preset set of ports, or get the bulk of UDP traffic diverted to it with
## firewall. It can then send the UDP traffic out locally, or tunnel this traffic remotely and send it
## out from there.
## It is useful A
##
## Terminology: Tiny UDP proxy receives the packets from clients, and sends them to remote peers
##

# REQUIRES: kldload ipdivert

## Sample divert ipfw rules
#${fwcmd} add 03018 divert 5060 log udp from 1.1.1.2 to any in via tap1
#${fwcmd} add 03018 allow log udp from any to 1.1.1.0/24 out via tap1


import sys, getopt
import os, pwd, grp
import socket,select
import array
import struct
import datetime
import random
import string
import signal
import time
import atexit
import hexdump
import net_checksums

##
## some options
##

do_log_packets=False
do_prn_packets=False

##
## Command line arguments and usage
##

arg_clnt_type=None
arg_clnt_divert_ip=None
arg_clnt_divert_port=None
arg_peer_type=None
arg_peer_local_ip=None
arg_cmd_up=None
arg_cmd_down=None

def usage():
    print('%s -c <client-spec> -p <peer-spec> {-u <cmd-up>} {-d <cmd-down>}' % (sys.argv[0]))
    sys.exit(2)

try:
    opts, args = getopt.getopt(sys.argv[1:], "c:p:u:d:",["client=","peer=","cmd-up=","cmd-down="])
except getopt.GetoptError:
    usage()
for opt,arg in opts:
    if opt in ("-c", "--client"):
        clnt_spec = arg.split(':')
        if not clnt_spec:
            print('client-spec is empty')
            usage()
        if clnt_spec[0] == 'divert':
            if len(clnt_spec) != 3:
                print('format of client-spec for divert: -c divert:IP:PORT')
                usage()
            arg_clnt_type = 'divert'
            arg_clnt_divert_ip = clnt_spec[1]
            arg_clnt_divert_port = int(clnt_spec[2])
        else:
            print("client-spec error: %s isn't supported" % (clnt_spec[0]))
            usage()
    elif opt in ("-p", "--peer"):
        peer_spec = arg.split(':')
        if not clnt_spec:
            print('client-spec is empty')
            usage()
        if peer_spec[0] == 'local':
            if len(peer_spec) != 2:
                print('format of peer-spec for local: -p local:ip')
                usage()
            arg_peer_type = 'local'
            arg_peer_local_ip = peer_spec[1]
        else:
            print("peer-spec error: %s isn't supported" % (peer_spec[0]))
            usage()
    elif opt in ("-u", "--cmd-up"):
        arg_cmd_up = arg
    elif opt in ("-d", "--cmd-down"):
        arg_cmd_down = arg

if arg_clnt_type == None:
    print('No client connection specified')
    usage()
if arg_peer_type == None:
    print('No peer connection specified')
    usage()

##
## options
##

peer_udp_port_lo=19000
peer_udp_port_hi=19299
heartbit_period_sec=1
idle_num_evts=100
opt_socket_expiration_ms=30000 # 30 sec

##
## stats
##

cnt_clnt_recv = 0
cnt_clnt_sent = 0
cnt_peer_recv = 0
cnt_peer_sent = 0

##
## Some basic log and time functions
##

def get_tm_ms():
    return int(round(time.time() * 1000))
def logfile():
    return '/var/log/tiny-udp-proxy.log'
def logfile_pkt():
    return '/var/log/tiny-udp-proxy-pkts.log'
def tm():
    return datetime.datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
def log(s):
    print("LOG %s" % (s))
    with open(logfile(), "a") as myfile:
        myfile.write('%s %s\n' % (tm(), s))
def log_pkt(is_req, ip, port, data):
    if do_log_packets:
        with open(logfile_pkt(), "a") as myfile:
            hstr=hexdump.hexdump(data, 'return')
            myfile.write("%s peer=%s:%d\n" % ('REQ' if is_req else "RES", ip, port))
            myfile.write(hstr)
            myfile.write("\n\n")
        
def log_discard(s):
    print("DISCARDED %s" % (s))
    with open(logfile(), "a") as myfile:
        myfile.write('packet discarded: %s %s\n' % (tm(), s))

###
### BEGIN Packet generator
###

def unpack_ip(ip):
    return ".".join(map(str, struct.unpack('BBBB', ip)))

def packet_new_ip_headers(proto, ip_src, ip_dst, pktid, remlen):
    # consts in the IP header
    version = 4
    ihl = 5 # Internet Header Length
    tos = 0 # Type of Service
    tl = 0x14+remlen
    flags = 0 # More fragments
    offset = 0
    ttl = 0x40 #255
    cksum = 0
    ver_ihl = (version << 4) + ihl
    flags_offset = (flags << 13) + offset
    # pack the header (little-endian for such broadcast packets)
    ip_header = bytearray(struct.pack("<BBHHHBBH4s4s",
                ver_ihl,
                tos,
                tl,
                pktid,
                flags_offset,
                ttl,
                proto,
                cksum,
                socket.inet_aton(ip_src),
                socket.inet_aton(ip_dst)))
    ip_header[10:12] = bytearray(struct.pack("H", socket.htons(net_checksums.checksum(ip_header))))
    return ip_header

def packet_new_udp_headers(port_src, port_dst, remlen):
    cksum=0
    header = bytearray(struct.pack("!HHHH",
                 port_src,
                 port_dst,
                 8+remlen,
                 cksum))
    return header

def packet_new_udp(ip_src, ip_dst, port_src, port_dst, pktid, payload_bytes):
    pkti = packet_new_ip_headers(socket.IPPROTO_UDP, ip_src, ip_dst, pktid, 8+len(payload_bytes))
    pktu = packet_new_udp_headers(port_src, port_dst, len(payload_bytes))
    return pkti+pktu+payload_bytes

###
### END Packet generator
###

# missing constants
socket_IPPROTO_DIVERT=258

## socket related structures
channels = {}
free_lports = list(range(peer_udp_port_lo, peer_udp_port_hi+1))
all_sockets_v = []
all_sockets_m = {}

##
## procedures
##

def alloc_lport():
    if free_lports:
        return free_lports.pop(0)
    else:
        return 0

def release_lport(lport):
    free_lports.append(lport)

def create_peer_socket(lport):
    try_cnt = 0
    while try_cnt < 5:
      try_cnt = try_cnt+1
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
      try:
          sock.bind((arg_peer_local_ip, lport))
          return sock
      except socket.error:
          log("bind on lport %u failed" % (lport))
    return None # port must be unavailable after several tries

def ept_to_str(ip_dst, port_dst):
    return "%s:%u" % (ip_dst, port_dst)

def get_channel(ip_src, port_src, ip_dst, port_dst):
    key = ept_to_str(ip_src, port_src)
    if key in channels:
        chan = channels[key]
        use_channel(chan)
        return chan
    else:
        # allocate port and create socket
        lport = alloc_lport()
        if lport == 0:
            # ran out of ports, ignore this
            log('ran out of lports, dropping client packet for '+key)
            return None
        peer_sock = create_peer_socket(lport)
        if peer_sock == None:
            log('failed to create socket, dropping client packet for '+key)
            release_lport(lport)
            return None
        all_sockets_v.append(peer_sock)
        # success: add the channel
        chan = {}
        chan['tm_created'] = get_tm_ms()
        chan['tm_last_pkt'] = chan['tm_created']
        chan['lport'] = lport
        chan['sock'] = peer_sock
        chan['ip_clnt'] = ip_src
        chan['ip_peer'] = ip_dst
        chan['port_clnt'] = port_src
        chan['port_peer'] = port_dst
        chan['pktid'] = int(0x10000*random.random())
        chan['cnt_out'] = 0 # number of packets tunnelled clnt->peer
        chan['cnt_in'] = 0 # number of packets tunnelled peer->clnt
        channels[key] = chan
        all_sockets_m[id(peer_sock)] = chan
        print('created the channel for %s with port %d' % (key,lport))
        return chan

def use_channel(chan):
    chan['tm_last_pkt'] = get_tm_ms()

def unpack_port(port_bytes):
    return socket.ntohs(struct.unpack('H', port_bytes)[0])

def recv_clnt(data,addr):
    global cnt_clnt_recv, cnt_peer_sent
    # full UDP packet is in data, packet IP is described as 'struct ip' (netinet/ip.h) is received as data, parse it:
    pkt_ip_src   = unpack_ip(data[12:16])
    pkt_ip_dst   = unpack_ip(data[16:20])
    pkt_port_src = unpack_port(data[20:22])
    pkt_port_dst = unpack_port(data[22:24])
    pkt_payload  = data[28:]
    if do_prn_packets:
        print("RECV from CLNT %s:%d to peer %s:%d raw-pkt.size=%d" % (pkt_ip_src, pkt_port_src, pkt_ip_dst, pkt_port_dst, len(data)))
    # find socket to send to
    chan = get_channel(pkt_ip_src, pkt_port_src, pkt_ip_dst, pkt_port_dst)
    if chan == None:
        return
    # send from ourselves
    chan['sock'].sendto(pkt_payload, (pkt_ip_dst, pkt_port_dst))
    # log
    log_pkt(True, pkt_ip_dst, pkt_port_dst, pkt_payload)
    if do_prn_packets:
        print('CLNT->PEER: %s:%d->{lport=%d}->%s:%d' % (chan['ip_clnt'], chan['port_clnt'], chan['lport'], pkt_ip_dst, pkt_port_dst))
    # count
    cnt_clnt_recv = cnt_clnt_recv+1
    cnt_peer_sent = cnt_peer_sent+1
    chan['cnt_out'] = chan['cnt_out']+1

def recv_peer(chan,data,addr):
    global cnt_peer_recv
    # create the complete IP/UDP packet
    chan['pktid'] = chan['pktid']+1 if chan['pktid']<65535 else 1
    pkt = packet_new_udp(addr[0], chan['ip_clnt'], chan['port_peer'], chan['port_clnt'], chan['pktid'], data)
    net_checksums.checksum_calc_udp_packet(pkt)
    # send the response back to client
    sock_clnt_w.sendto(pkt, (chan['ip_clnt'], chan['port_clnt']))
    # log
    log_pkt(False, chan['ip_peer'], chan['port_peer'], data)
    if do_prn_packets:
        print('PEER->CLNT: %s:%d->{lport=%d}->%s:%d' % (chan['ip_peer'], chan['port_peer'], chan['lport'], chan['ip_clnt'], chan['port_clnt']))
    # count
    cnt_peer_recv = cnt_peer_recv+1
    chan['cnt_in'] = chan['cnt_in']+1

def on_idle():
    global channels, all_sockets_v, all_sockets_m, free_lports
    # delete too old channels and release their sockets
    tm_now = get_tm_ms()
    new_all_sockets_v = []
    new_all_sockets_v.append(sock_clnt)
    keys_to_delete = {}
    cnt_exp = 0
    cnt_lve = 0
    for key,chan in channels.items():
        if chan['tm_last_pkt'] + opt_socket_expiration_ms < tm_now:
            release_lport(chan['lport'])
            del all_sockets_m[id(chan['sock'])]
            keys_to_delete[key] = None
            cnt_exp = cnt_exp+1
        else:
            new_all_sockets_v.append(chan['sock'])
            cnt_lve = cnt_lve+1
    for key in keys_to_delete.keys():
        chan = channels[key]
        print('destroyed the channel for %s with port %d (expired after %d sec, cnt-in=%d, cnt-out=%d)'
              % (key,chan['lport'],opt_socket_expiration_ms/1000, chan['cnt_in'], chan['cnt_out']))
        del channels[key]
    all_sockets_v = new_all_sockets_v

def run_cmd_down():
    global arg_cmd_down
    res = os.system(arg_cmd_down)
    if res != 0:
        print('%s: Failed to run cmd-down!' % (sys.argv[0]))

def create_sock_divert(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_IPPROTO_DIVERT)
    sock.bind((ip, port))
    return sock

def create_sock_raw_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock

##
## MAIN cycle
##

# run cmd-up if any
if arg_cmd_up != None:
    res = os.system(arg_cmd_up)
    if res != 0:
        print('%s: Failed to run cmd-up!' % (sys.argv[0]))
        sys.exit(3)
    if arg_cmd_down != None:
        atexit.register(run_cmd_down)

# create sockets
sock_clnt = create_sock_divert(arg_clnt_divert_ip, arg_clnt_divert_port)
all_sockets_v.append(sock_clnt)
sock_clnt_w = create_sock_raw_ip()

# main event loop
while True:
    # select
    (ii,oo,ee) = select.select(all_sockets_v,[],[], heartbit_period_sec)
    for sock_ready in ii:
        (data, addr) = sock_ready.recvfrom(64000, 1024)
        if sock_ready == sock_clnt:
            recv_clnt(data, addr)
        else:
            recv_peer(all_sockets_m[id(sock_ready)], data, addr)
    # idle
    if not ii:
        on_idle()
    elif (cnt_clnt_recv+cnt_peer_recv)%idle_num_evts == 0:
        on_idle()

