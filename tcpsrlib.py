# Copyright (C) 2010 WIDE Project.  All rights reserved.
#
# Michio Honda  <micchie@sfc.wide.ad.jp>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import socket
import struct
import select
import errno
import os
import sys
import threading
import time
import re
import commands
import random
import tcplib
import pcaplib

#
# returns source address to the given destination
#
def getsaddr(daddr):
    try: 
        ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except socket.error:
	print "Error: failed to create socket to lookup laddr"
	return 0
    try:
        ss.connect((socket.inet_ntop(socket.AF_INET, \
					struct.pack('!L', daddr)), 34343))
    except socket.error:
	print "Error: failed to init socket to lookup laddr"
	return 0
    laddr = ss.getsockname()[0]
    ss.close()
    return struct.unpack('!L', socket.inet_pton(socket.AF_INET, laddr))[0]

#
# return destaddr, localhostname, localhostaddr
# addresses are formatted to host-byteorder integer 
#
def gethostpair(dhost):
    daddr = 0
    laddr = 0
    lhost = ""

    try:
        daddr_str = socket.gethostbyname(dhost)
	daddr = struct.unpack('!L', \
			socket.inet_pton(socket.AF_INET, daddr_str))[0]
    except socket.gaierror:
        print "Error: can't lookup an address of given remote host"
	return daddr, lhost, laddr

    try:
        lhost = socket.getfqdn()
    except socket.gaierror:
        print "Error: no hostname is assigned to the local host"
	lhost = ""
    try:
        laddr = getsaddr(daddr)
    except socket.gaierror:
        print "Error: can't lookup an address of the local host"
    return daddr, lhost, laddr
    
#
# MAC address related utilities for using pcap
#
def is_macaddr_str(_str):
    tmp = _str.split(':')
    if len(tmp) < 6:
	return 0

    for w in tmp:
        for i in range(0, len(w)):
	    if re.match('[A-Fa-f0-9]', w[i]) == None:
		return 0
    return 1

def get_ifname_and_smacaddr(saddr):
    err = 0
    plib = pcaplib.pcaplib()
    if plib.lib == None:
        print "Error: failed to load libpcap"
	return "", 0, -1
    devs, err = plib.Pcap_findalldevs()
    if err:
	return "", 0, err
    ostype = os.uname()[0]
    
    ifname = ""
    smacaddr = 0
    found = 0
    for dev in devs:
        if len(dev) < 2: 
	    continue
        for addr in dev[1:len(dev)]:
            if addr[0] == socket.AF_INET and addr[1] == saddr:
	        ifname = dev[0]
		for tmp in dev[1:len(dev)]:
		    if ((ostype == 'FreeBSD' or ostype == 'Darwin') and \
			tmp[0] == 18) or \
			ostype == 'Linux' and tmp[0] == 17:
		        smacaddr = tmp[1]
			break
		return ifname, smacaddr, 0
    return ifname, smacaddr, -1

def get_dmacaddr(ifname, ipdst):

    dmac_str = ''
    ipdst_str = socket.inet_ntop(socket.AF_INET, struct.pack('!L', ipdst))

    # Create ARP cache for destination or gateway
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    s.sendto("*", (ipdst_str, 50000))
    s.close()
    time.sleep(0.2)

    ostype = os.uname()[0]
    os.putenv('LANG', 'C')
    os.putenv('PATH', '/bin:/sbin:/usr/bin:/usr/sbin:$PATH')

    if ostype == 'FreeBSD' or ostype == 'Darwin':
        cmd = 'route -n get %s | grep gateway | sed s/\' \'/\'\'/g | cut -d\':\' -f2'%ipdst_str
        nxthop = commands.getoutput(cmd)
        if nxthop == '':
	    nxthop = ipdst_str
#        cmd = 'arp -n -i %s %s | cut -d\' \' -f4'%(ifname, nxthop)
	cmd = 'arp -an | grep \'(%s)\' | cut -d\' \' -f4'%nxthop
        dmac_str = commands.getoutput(cmd).split('\n')[0]

    elif ostype == 'Linux':
        cmd = 'arp -n -i %s %s | grep %s | sed s/\' \{2,\}\'/\' \'/g'%(ifname, ipdst_str, ifname)
	arpent = commands.getoutput(cmd)

	if arpent == '':
	    cmd = 'netstat -rnA inet | grep ^0.0.0.0 | grep %s | sed s/\' \{2,\}\'/\' \'/g | cut -d\' \' -f2'%ifname
	    nxthop = commands.getoutput(cmd)
            cmd = 'arp -i %s -n %s | grep %s | sed s/\' \{2,\}\'/\' \'/g |cut -d\' \' -f3'%(ifname, nxthop, ifname)
            dmac_str = commands.getoutput(cmd)
	else:
	    dmac_str = arpent.split(' ')[2]
    if is_macaddr_str(dmac_str) == 0:
        print "Error: obtained address from commands is not a MAC address"
	print dmac_str
        return 0

    tmp = re.split(':', dmac_str)
    for c in range(0, len(tmp)):
	if len(tmp[c]) == 1:
	    tmp[c] = '0' + tmp[c]
    s = '%s'%tmp
    s = re.sub('\'\, \'', ':', s)
    s = re.sub('\[\'', '', s)
    s = re.sub('\'\]', '', s)
    return tcplib.ether_ptoh(s)

#
# pack and unpack tcp options
#
def compose_options(options):
    tcpsoption = ""
    avail_opt_len = 40
    for opt in options:
	if opt[0] == 'NOP':
	    if avail_opt_len < 1: 
		break
	    nop = tcplib.create_nop()
	    tcpsoption += nop
	    avail_opt_len -= 1
	    continue
        if opt[0] == 'MSS':
	    if avail_opt_len < 4: 
		break
	    mssoption = tcplib.create_mss(opt[1])
	    tcpsoption += mssoption
	    avail_opt_len -= 4
	    continue
        if opt[0] == 'WSCALE':
	    if avail_opt_len < 3: 
		break
	    wsoption = tcplib.create_winscale(opt[1])
	    tcpsoption += wsoption
	    avail_opt_len -= 3
	    continue
	if opt[0] == 'SACKOK':
	    if avail_opt_len < 2: 
		break
	    sackok_option = tcplib.create_sackok()
	    tcpsoption += sackok_option
	    avail_opt_len -= 2
	    continue
	if opt[0] == 'TIMESTAMP':
	    if avail_opt_len < 10: 
		break
	    tsoption = tcplib.create_timestamp(opt[1], opt[2])
	    tcpsoption += tsoption
	    avail_opt_len -= 10
	    continue
	if opt[0] == 'MP_CAPABLE':
	    if avail_opt_len < 12: 
		break
	    mpcap_option = tcplib.create_mpcapable(opt[1], opt[2])
	    tcpsoption += mpcap_option
	    avail_opt_len -= 12
	    continue
	if opt[0] == 'MP_DATA':
	    if avail_opt_len < 16: 
		break
	    # (Dsn (8 Byte), Dlen (2 Byte), Ssn(4 Byte))
	    dsn_option = tcplib.create_mpdata(opt[1], opt[2], opt[3]) 
	    tcpsoption += dsn_option
	    avail_opt_len -= 16
	    continue
	if opt[0] == 'MP_ACK':
	    if avail_opt_len < 10: 
		break
	    dataack_option = tcplib.create_mpack(opt[1])
	    tcpsoption += dataack_option
	    avail_opt_len -= 10
	    continue

    tcpsoption += tcplib.check_padding(tcpsoption)
    return tcpsoption

def decompose_options(ofield):
    tcpoptions = []
    olen = len(ofield)
    if olen == 0: 
	return tcpoptions
    # Sequentially parse each option 
    idx = 0
    while olen > 0:
        if len(ofield[idx:idx+1]) == 0:
	    break
	kind = struct.unpack('b', ofield[idx:idx+1])[0]
	if kind == 0:
	   tcpoptions.append(['EOL',''])
	elif kind == 1:
	   tcpoptions.append(['NOP',''])
	if kind == 0 or kind == 1:
	    idx += 1
	    olen -= 1
	    continue
	optlen = struct.unpack('b', ofield[idx+1: idx+2])[0]

	if kind == tcplib.TO_MSS and olen >= 4:
	   mss = tcplib.unpack_mss(ofield[idx+2: idx+4])
	   tcpoptions.append(['MSS', mss])

	elif kind == tcplib.TO_WSCALE and olen >= 3:
	   wscale = tcplib.unpack_winscale(ofield[idx+2: idx+3])
	   tcpoptions.append(['WSCALE', wscale])

	elif kind == tcplib.TO_SACKOK and olen >= 2:
	   tcpoptions.append(['SACKOK', ''])

	elif kind == tcplib.TO_TIMESTAMP and olen >= 10:
	   tsval, tsecr = tcplib.unpack_timestamp(ofield[idx+2: idx+10])
	   tcpoptions.append(['TIMESTAMP', tsval, tsecr])

	elif kind == tcplib.TO_MP_CAPABLE and olen >= 12:
	   token, idsn = tcplib.unpack_mpcapable(ofield[idx+2: idx+12])
	   tcpoptions.append(['MP_CAPABLE', token, idsn])

	elif kind == tcplib.TO_MP_DATA and olen >= 16:
	   dseq, dlen, sseq = tcplib.unpack_mpdata(ofield[idx+2: idx+16])
	   tcpoptions.append(['MP_DATA', dseq, dlen, sseq])

	elif kind == tcplib.TO_MP_ACK and olen >= 10:
	   dack = tcplib.unpack_mpack(ofield[idx+2: idx+10])
	   tcpoptions.append(['MP_ACK', dack])

	idx += optlen
	olen -= optlen

    return tcpoptions

#
# obtain structured format of a single TCP segment
# 
def parse_headers(pkt):
    ipdata = pkt[0:20]
    iph = tcplib.iphdr()
    iph.parsehdr(ipdata)

    tcpheader = pkt[iph.hdrlen:iph.hdrlen+20]
    tcph = tcplib.tcphdr()
    tcph.parsehdr(tcpheader)
    tcpofields = pkt[iph.hdrlen + 20 : iph.hdrlen + tcph.hdrlen]
    tcpoptions = decompose_options(tcpofields)

    payload = pkt[iph.hdrlen + tcph.hdrlen : len(pkt)]

    return iph, tcph, tcpoptions, payload

def parse_ether_header(frm):
    etherdata = frm[0:14]
    etherh = tcplib.etherhdr()
    etherh.parsehdr(etherdata)
    payload = frm[14:len(frm)]

    return etherh, payload

#
# packet logging/debugging methods
#
def summarize_pkt(pkt):
    ans1 = parse_headers(pkt)
    return summarize_ans1(ans1)

def summarize_ans1(ans1):
    if len(ans1) != 4 and len(ans1) != 3: 
	return ""

    if len(ans1) == 4:
        iph, tcph, tcpoption, payload = ans1
    elif len(ans1) == 3:
        iph, tcph, tcpoption = ans1
    s = ""
    s += '%s.%d > %s.%d: '%(socket.inet_ntop(socket.AF_INET, \
		    struct.pack('!L', iph.srcaddr)), tcph.srcport, \
		    socket.inet_ntop(socket.AF_INET, \
		    struct.pack('!L', iph.dstaddr)), tcph.dstport)
    s += 'Flags [0x%x], '%tcph.flag 
    s += 'seq %d, ack %d, '%(tcph.seqno, tcph.ackno)
    s += 'win %d, '%tcph.window
    if len(tcpoption) > 0:
        opt_str = '%s ,'%tcpoption
        opt_str = re.sub('\[', '', opt_str)
        opt_str = re.sub('\]', '', opt_str)
        opt_str = re.sub('\'', '', opt_str)
	opt_str = re.sub(' ,', '', opt_str)
        s += "options [" + opt_str + "], "
    s += 'length %d, '%(iph.length - iph.hdrlen - tcph.hdrlen)
    s += 'pktlen %d, iphdrlen %d, tcphdrlen %d checksum 0x%x'%(iph.length, iph.hdrlen, \
		    tcph.hdrlen, tcph.checksum)
    s += '\n'
    return s

#
# packet analyzing utilities
#
def is_connection_reset(ans):
    for rcv in ans:
	if rcv[1].flag & tcplib.TH_RST:
	    return 1
    return 0

def get_synack(ans):
    for rcv in ans:
	if rcv[1].flag & tcplib.TH_SYN and rcv[1].flag & tcplib.TH_ACK: 
	    return rcv
    return None

def get_ack_for_fin(ans):
    for rcv in ans:
	if rcv[1].flag & tcplib.TH_FIN: 
	    continue
	elif rcv[1].flag & tcplib.TH_ACK: 
	    return rcv
    return None

def get_fin(ans):
    for rcv in ans:
	if rcv[1].flag & tcplib.TH_FIN and rcv[1].flag & tcplib.TH_ACK: 
	    return rcv
    return None

def get_acklist(ans):
    acks = []
    for rcv in ans:
	if rcv[1].flag & tcplib.TH_SYN or rcv[1].flag & tcplib.TH_FIN or \
		   rcv[1].flag & tcplib.TH_RST:
	    continue
        acks.append(rcv[1].ackno)
    return acks

def get_dataacklist(ans):
    dataacks = []
    for rcv in ans:
	for opt in rcv[2]:
	    if opt[0] == 'MP_DATA': dataacks.append(opt[1])
    return dataacks

def get_dupacklist(ans):
    acks = get_acklist(ans)
    dupacks = []
    i = 0
    skip = 0
    while i < len(acks):
	skip = 0
	j = 0
	while j < len(dupacks):
	    if acks[i] == dupacks[j]:
	        skip = 1
	        break
	    j += 1

	j = i + 1
        while j < len(acks) and skip == 0:
	    if acks[j] == acks[i]: dupacks.append(acks[j])
	    j += 1
	i += 1
    return dupacks

def get_highest_ack(ans):
    highest_ack = 0
    acks = get_acklist(ans)
    for ack in acks:
	if ack > highest_ack: highest_ack = ack
    return highest_ack

def get_highest_seq(ans):
    highest_seq = 0
    for ent in ans:
	if ent[1].seqno > highest_seq: highest_seq = ent[1].seqno
    return highest_seq

def get_mss_from_tcpopt(options):
    for opt in options:
        if opt[0] == 'MSS': return opt[1]
    return 0

# returns [token, idsn]
def get_mpcap_from_tcpopt(options):
    rcvtoken = 0
    rcvidsn = 0
    for opt in options:
        if opt[0] == 'MP_CAPABLE': 
	    rcvtoken = opt[1]
	    rcvidsn = opt[2]
	    break
    return rcvtoken, rcvidsn
	
def get_dataacks_from_tcpopt(options):
    dataacks = []
    for opt in options:
	if opt[0] == 'MP_ACK': 
	    dataacks.append(opt[1])
    return dataacks

def get_valid_dataacks_from_tcpopt(options):
    valid_dataacks = get_dataacks_from_tcpopt(options)
    idx = 0
    for dack in valid_dataacks:
        if dack == 0x0000000000000000: valid_dataacks.pop(idx)
	idx += 1
    return valid_dataacks

def are_segments_lost_from_acks(startseq, sentsegs, ans):
    lost = 0
    acks = get_acklist(ans)
    if len(acks) == 0: return 1
    expack = startseq
    for i in sentsegs:
	found = 0
	expack += i
	for j in acks:
	    if j == expack: 
	        found = 1
	        break
	if found == 0: 
	    lost = 1
	    break
    return lost

def are_segments_lost(ans, startseq, sentsegs):
    return are_segments_lost_from_acks(startseq, sentsegs, ans)
    # Under consideration how to detect losses...

#
# compose a single TCP segment from given parameters 
# (TCP options and payload are optional)
# Options are must be described as a list consisting of tuples for each option
# recognized by compose_options() in this file. 
# E.g., [('MSS', 512), ('TIMESTAMP', 12345, 67891)]
#
def make_segment(daddr, saddr, dport, sport, awnd, seq, ack, flags, options=(), payload=None, ipcksum=0):

    segment = ""

    if payload == "": 
	payload = None
    soptions = compose_options(options)

    ipid = random.randrange(0x0001, 0xfffe)
    ipttl = 255
    iplen = tcplib.BASEHDRLEN + len(soptions) 
    if payload != None: 
	iplen += len(payload)
    iph = tcplib.iphdr(saddr, daddr, iplen, ipid, ipttl)
    # If we use RAW socket, we don't need to calculate checksum, but if we use
    # Pcap, we need to calculate it
    if ipcksum:
        iph.calccksum()

    tcph = tcplib.tcphdr(sport, dport, seq, ack, flags, awnd, soptions)
    tcph.calccksum(iph, payload)
    segment += iph.bin()
    segment += tcph.bin()
    if payload != None: 
        segment += payload

    return segment

#
# transmit packets to the given destination 
# 
    
def pcap_send_segments(ifname, pkts, smacaddr=0, dmacaddr=0, sent=None):
    # Open pcap descripter
    plib = pcaplib.pcaplib()
    if plib.lib == None:
        print "Error: failed to load libpcap"
	return -1
    descrip = plib.Pcap_open_live(ifname)
    if descrip == None:
        print "Error: failed to open pcap descripter"
	return -1

    # Compose packets including datalink header
    frms = []
    dltype = plib.Pcap_datalink(descrip)
    for pkt in pkts:
        frm = ""
        if dltype == pcaplib.DLT_EN10MB:
	    etherh = tcplib.etherhdr(dmacaddr, smacaddr, 0x0800)
	    frm = etherh.bin()
	elif dltype == pcaplib.DLT_PPP or (dltype == 0 and re.match('ng[0-9]', ifname)):
	    frm = struct.pack('!BBBB', 0xff, 0x03, 0x00, 0x21)
	else:
	    print "Error: unsupported link type"
	    return -1
	frm += pkt
	frms.append(frm)

    # Send frames
    for frm in frms:
        err = plib.Pcap_inject(descrip, frm, len(frm))
	if err < 0:
	    plib.Pcap_close(descrip)
            print "Error: pcap_inject failed"
	    return -1

    if sent != None:
        sent.set()
    plib.Pcap_close(descrip)
    return 0

# If we use pcap, packets MUST include ether header and interface name MUST be 
# given 
def send_segments(daddr, pkts, usepcap=0, ifname="", smacaddr=0, dmacaddr=0, sent=None):
    if usepcap == 1:
	if ifname == "":
            print "Error: No ifname is given to use pcap for send_segments"
	    return -1
	err = pcap_send_segments(ifname, pkts, smacaddr, dmacaddr)
	return err
    err = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    daddr_str = socket.inet_ntop(socket.AF_INET, struct.pack('!L', daddr))
    for pkt in pkts:
        try: s.sendto(pkt, (daddr_str, 0))
	except (socket.error, OSError): 
	    err = -1
	    break
    if sent != None:
	sent.set()
    s.close()
    return err

#
# transmit packets and observe reply packets (i.e., corresponding port numbers)
# return a list consisting of [iph, tcph, payload]
#

PCAP_BREAK_DPORT = 50510
def send_pcapbreak(pkt, stopped):

    if stopped.isSet():
        return

    iph, tcph, tcpo, payload = parse_headers(pkt)
    ipdst_str = socket.inet_ntop(socket.AF_INET, struct.pack('!L', iph.dstaddr))
    ipsrc_str = socket.inet_ntop(socket.AF_INET, struct.pack('!L', iph.srcaddr))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	s.bind(('',tcph.srcport))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    except (socket.error, socket.gaierror):
	print "Warn: cannot operate sending packets to break pcap loop"
	return

    retry = 0.4
    for i in range(0, 5):
        s.sendto("*", (ipdst_str, PCAP_BREAK_DPORT))
	stopped.wait(retry)
	if stopped.isSet():
	    break
	retry *= 2
    s.close()

#    if stopped.isSet() is False:
#        print "Warn: break packet is not handled"
    return

def pcap_sendrecv_segments(ifname, pkts, timeout=1.0, sflags=0, \
		smacaddr=0, dmacaddr=0):
    rcvfrms = []
    rcvpkts = []
    err = 0

    # Open pcap descripter
    plib = pcaplib.pcaplib()
    if plib.lib == None:
        print "Error: failed to load libpcap"
	return rcvpkts, -1
    to_ms = int(1.0*1000)
    descrip = plib.Pcap_open_live(ifname, to_ms=to_ms)
    if descrip == None:
        print "Error: failed to open pcap descripter"
	return rcvpkts, -1

    dltype = plib.Pcap_datalink(descrip)

    # Set bpf filter
    iph, tcph, tcpo, payload = parse_headers(pkts[0])
    filter ='(src host %s and src port %d and dst port %d and udp and ip[8] = 1) or '%\
	    (socket.inet_ntop(socket.AF_INET, struct.pack('!L', iph.srcaddr)), \
	     tcph.srcport, PCAP_BREAK_DPORT)
    filter += '(ip[8] > 1 and src host %s and src port %d and dst host %s and dst port %d and tcp'%\
		  (socket.inet_ntop(socket.AF_INET, \
		   struct.pack('!L', iph.dstaddr)), tcph.dstport, 
		   socket.inet_ntop(socket.AF_INET, \
		   struct.pack('!L', iph.srcaddr)), tcph.srcport)
    if (sflags & tcplib.TH_SYN) is True:
        filter += ' and tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'
    filter += ')'

    err = plib.Pcap_compile(descrip, filter)
    if err != 0:
	plib.Pcap_close(descrip)
        print "Error: failed to set pcap filter"
	return rcvpkts, -1

    sent = threading.Event()
    th = threading.Thread(target=pcap_send_segments, args=(ifname, tuple(pkts), smacaddr, dmacaddr, sent))
    th.setDaemon(True)

    # In some platforms (e.g., old Linux), timeout at open_live doesn't work
    # We define the killer packet to force finish pcap reading packets
    stopped = threading.Event()
    stopper = threading.Timer(timeout , send_pcapbreak, args=(pkts[0], stopped))
    stopper.start()

    th.start()
    while True:
        err, rcvfrm = plib.Pcap_next_ex(descrip)
	if err > 0:
	    # Quick check of TTL and Protocol in IP header
	    if dltype == pcaplib.DLT_EN10MB:
	        if struct.unpack('!BB', rcvfrm[22:24]) == (1, 17):
	            err = -2
	            break
	    elif dltype == pcaplib.DLT_PPP:
	        if struct.unpack('!BB', rcvfrm[12:14]) == (1, 17):
	            err = -2
	            break
	    rcvfrms.append(rcvfrm)
	    if sflags & tcplib.TH_SYN:
	        break
	    continue
	elif err == 0:
	    continue
	elif err == -2:
	    break
	elif err == -1:
            print "Error: failed in pcap_next_ex"
	    break
    if sent.isSet() == False:
        print "Error: timeout in pcap_send_segments"
	err = -1
    stopper.cancel()
    stopped.set()
    th.join()

    plib.Pcap_close(descrip)
    if err == -1:
        return rcvpkts, -1

    for rcvfrm in rcvfrms:
        if dltype == pcaplib.DLT_EN10MB:
            etherhdr, pkt = parse_ether_header(rcvfrm)
	elif dltype == pcaplib.DLT_PPP:
	    pkt = rcvfrm[4:]
	iph, tcph, tcpo, payload = parse_headers(pkt)
	rcvpkts.append((iph, tcph, tcpo, payload))

    return rcvpkts, 0

# packets MUST include ether header and interface name MUST be given 
# if we use pcap
def sendrecv_segments(daddr, pkts, timeout=1.0, sflags=0, \
		usepcap=0, ifname="", smacaddr=0, dmacaddr=0):
    if usepcap == 1:
	if ifname == "":
            print "Error: No ifname is given to use pcap for sendrecv_segments"
	    return [], -1
	rcvpkts, err = pcap_sendrecv_segments(ifname, pkts, timeout, sflags, \
			smacaddr, dmacaddr)
	return rcvpkts, err

    tmp_rcvpkts = []
    rcvpkts = []
    err = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    myiph, mytcph, myopts, mypayload = parse_headers(pkts[0])
    mydport = mytcph.dstport
    mysport = mytcph.srcport
    mydaddr = myiph.dstaddr
    mysaddr = myiph.srcaddr

    sent = threading.Event()
    th = threading.Thread(target=send_segments, args=(daddr, pkts, 0, "", 0, 0, sent))
    th.setDaemon(True)
    th.start()
    start = time.time()
    while True:
	if time.time() - start > timeout: 
	    break
	try: 
	    inputready,outputready,exceptready = select.select([s], [], [], 1)
	except select.error, e:
	    print "Warn: select.error"
	    if e[0] == errno.EINTR: continue
	    else: break
	if len(inputready) == 0: continue
	try: (rcvdata, recvaddr) = s.recvfrom(65565)
	except (socket.error, OSError): 
	    err = -1
	    break
	
	iph = tcplib.iphdr()
	iph.parsehdr(rcvdata[0:20])
	tcph = tcplib.tcphdr()
	tcph.parsehdr(rcvdata[iph.hdrlen:iph.hdrlen+20])

	if tcph.srcport != mydport or tcph.dstport != mysport or \
		iph.srcaddr != mydaddr or iph.dstaddr != mysaddr:
	    continue
	# ignore 1 ttl packet, because it could be generated by dummy socket
	elif iph.ttl == 1:
	    continue
	tmp_rcvpkts.append(rcvdata)

	if (sflags & tcplib.TH_SYN) and \
		(tcph.flag & (tcplib.TH_SYN | tcplib.TH_ACK)):
	    break
    if sent.isSet() == False:
        print "Error: timeout in send_segments"
	err = -1
    s.close()
    if err:
	return rcvpkts, err

    for data in tmp_rcvpkts:
        iph, tcph, tcpo, payload = parse_headers(data)
	rcvpkts.append((iph, tcph, tcpo, payload))
    return rcvpkts, err

