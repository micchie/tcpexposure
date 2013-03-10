#
# Yoshifumi Nishida  <nishida@sfc.wide.ad.jp>
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
import signal
import select
import errno
import os 
import sys 
import tcplib

import threading
import commands
import time
import pcaplib
import httpenc

#MPTCP_PORT = 34343

P_LINUX = 0
P_PLAB = 1

platform = 0

#
# address 
#
def getaddress(targetstr):
   if len(targetstr) == 0:
      deststr = socket.gethostbyname(socket.gethostname())
      dest = socket.inet_aton(deststr)
   else:
      if str.isdigit(targetstr[0:1]) :
         deststr = "".join(socket.gethostbyaddr(targetstr)[2])
         dest = socket.inet_aton(deststr)
      else:
         deststr = socket.gethostbyname(targetstr)
         dest = socket.inet_aton(deststr)
  
   ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
   ss.connect((deststr, MPTCP_PORT))
   src = struct.unpack('!L',socket.inet_aton(ss.getsockname()[0]))[0]
   dest = struct.unpack('!L',socket.inet_aton(deststr))[0]
   
   return (src, dest)

#
# tcp options
#
MSSval = 512
WSval = 6
TSval = 12345678
SynTsEcr = 0xffff0000 # Initiator's value

mssoption = tcplib.create_mss(MSSval)
wsoption = tcplib.create_winscale(WSval)
tsoption = tcplib.create_timestamp(TSval,0)
sackokoption = tcplib.create_sackok()

#
# mpcapable option
#
mptcp_token = 0x0D0C0B0A
mptcp_isn = 0x0102030405060000
mpcap_option = tcplib.create_mpcapable(mptcp_token, mptcp_isn)

#
# constants for ip and tcp header
#
ipid = 0x4321
ipttl = 255
otcpseqno = 0xabcdef
tcpseqno = 0xabcdef
tcpwindow = 32768

#
# special hack parameters
# 
request_hdrdata = 0xa1
request_hdrdata_http = 0xa3
request_dupack = 0xb2
Adv_syndata_ack = 0xc1
Hdrdata_and_advsyndata_ack = 0xc2
request_differ_tsecr = 0xa2

#
# Planetlab specific functions
#
PEEP_BREAK_DPORT = 24000
UDP_FLOOD_CTL_PORT = 35000
UDP_FLOOD_DPORT = 24001
FLOOD_UDP_START = 0x00000001
FLOOD_UDP_STOP = 0x00000002
FLOOD_UDP_CONFIRMED = 0x00000003
Accepted_list = []
def close_accepted_so(raddr, rport):
    idx = -1
    found = 0
    for ent in Accepted_list:
	idx += 1
	if raddr == ent[0] and rport == ent[1]:
	    try:
	        ent[2].close()
	    except (socket.error, socket.herror, socket.gaierror):
#		print "Warn: failed to close dummy connection"
		pass
	    found = 1
	    break
    if idx >= 0 and found:
        Accepted_list.pop(idx)
#    elif found == 0:
#	print "Warn: cannot find corresponding connection"

# Store (daddr, dport, isn) of peeped synack in recent 10 (first is recent)
Peeped_synacks = []
Peeper_lock = threading.Lock()
def peep_os_synack():

    global Peeped_synacks

    Peeper_lock.acquire()
    for i in range(0, 10):
        Peeped_synacks.append((0,0,0))
    Peeper_lock.release()

    os.putenv('LANG', 'C')
    os.putenv('PATH', '/bin:/sbin:/usr/bin:/usr/sbin:$PATH')
    cmd = 'netstat -rn | grep ^0.0.0.0 | sed s/\' \{2,\}\'/\' \'/g | cut -d\' \' -f2,8' 
    s = commands.getoutput(cmd)
    (nxthop_str, dummy, ifname) = s.partition(' ')
    try:
        fqdn = socket.getfqdn()
    except socket.gaierror:
        sys.exit(1)
    try:
        saddr_str = socket.gethostbyname(fqdn)
    except socket.gaierror:
        sys.exit(1)

    plib = pcaplib.pcaplib()
    if plib.lib == None:
	return
    descrip = plib.Pcap_open_live(ifname, to_ms=4000)
    if descrip == None:
	return
    filter = '(ip[8] = 1 and src host %s and src port %d and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0) or (ip[8] = 1 and src host %s and dst port %d and udp)'%(saddr_str, MPTCP_PORT, saddr_str, PEEP_BREAK_DPORT)

    err = plib.Pcap_compile(descrip, filter)
    if err != 0:
        plib.Pcap_close(descrip)
	return
    
    while True:
        err, rcvfrm = plib.Pcap_next_ex(descrip)
	if err > 0:
	    ttl, proto = struct.unpack('!BB', rcvfrm[22:24])
	    # handling breaking packet (1-TTL UDP packet to BREAK_DPORT)
	    if ttl == 1 and proto == 17:
		err = -2
		break
	    # handling reset for managing accepted list
	    # quick filtering of SYNACK from OS by TTL
	    elif ttl != 1 or proto != 6:
		continue
	    Peeper_lock.acquire()
	    Peeped_synacks.pop(0)
	    Peeped_synacks.append((struct.unpack('!L', rcvfrm[30:34])[0], \
				    struct.unpack('!H', rcvfrm[36:38])[0], \
				    struct.unpack('!L', rcvfrm[38:42])[0]))
	    Peeper_lock.release()
	    continue
	elif err == 0:
	    continue
	elif err == -2 or err == -1:
#	    print 'Error: pcap_next_ex returned %d'%err
	    break
    plib.Pcap_close(descrip)
    return

Fld_udp_on = threading.Event()
def flood_udp():
    Fld_udp_on.set()
    start = time.time()
    udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udpsock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    payload = "a"
    while Fld_udp_on.isSet() == True:
        udpsock.sendto(payload, ('8.8.8.8', UDP_FLOOD_DPORT))
#	time.sleep(0.0002)
	if time.time() - start > 5400:
	    Fld_udp_on.clear()
	    break
#    print "Info: Fld_udp_on has been cleaned, return"
    udpsock.close()

#
# function to send back packets
#
def send_packet():
   global tcpsoption
   ackno = tcpackno

   # add padding to tcp option
   tcpsoption += tcplib.check_padding(tcpsoption)

   # special hack parse
   sdata = ""
   if datalen > 3 or (len(data) > 1 and tcpflag & tcplib.TH_SYN): 
       trimmed, http = httpenc.trim_httphdr(data)
       if not http and \
           struct.unpack('!B', trimmed[0:1])[0] == request_hdrdata_http:
           http = 1
       if http and httpenc.is_http_get(data, 'hoge.cgi'):
	   sdata = httpenc.httphdr_ok_dummy()
       elif len(trimmed) == 0:
           pass
       elif struct.unpack('!B', trimmed[0:1])[0] == request_dupack:
	   ackno = tcph.seqno
       elif struct.unpack('!B', trimmed[0:1])[0] == request_differ_tsecr or \
       	    struct.unpack('!B', trimmed[0:1])[0] == request_hdrdata or \
       	    struct.unpack('!B', trimmed[0:1])[0] == request_hdrdata_http or \
	    struct.unpack('!B', trimmed[0:1])[0] == Hdrdata_and_advsyndata_ack:
           if struct.unpack('!B', trimmed[0:1])[0] == request_differ_tsecr:
	       tcpsoption = tcplib.create_timestamp(TSval, tsecr-1)
	       tcpsoption += tcplib.check_padding(tcpsoption)
           target_len = 512 - len(tcpsoption)
	   if tcpflag & tcplib.TH_SYN:
	       target_len = len(data)
	   # Prepare HTTP OK header
           if http:
	       sdata = httpenc.httphdr_ok(target_len)
           # Prepare receiving headers
           sdata += rcvhdrdata
           # Prepare sending headers (IP and TCP checksums are zero)
	   tmpiph = tcplib.iphdr(ipsrc, ipdest, tcplib.BASEHDRLEN + 512, \
			   ipid, ipttl)
	   tmptcph = tcplib.tcphdr(tcpsport, tcpdport, tcpseqno, ackno, \
			   tcpflag, tcpwindow, tcpsoption)
	   sdata += tmpiph.bin() + tmptcph.bin() 
	   cur_len = len(sdata)
	   if len(trimmed) >= target_len - cur_len:
	       sdata += trimmed[0: target_len - cur_len]
	   else:
	       sdata += trimmed
	       cur_len += len(trimmed)
	       for i in range(0, target_len - cur_len):
		   sdata += struct.pack('!B', 0xAB)

   # prepare ip header
   iplen = tcplib.BASEHDRLEN + len(tcpsoption) + len(sdata)
   iphs = tcplib.iphdr(ipsrc, ipdest, iplen, ipid, ipttl)

   # prepare tcp header
   tcphs = tcplib.tcphdr(tcpsport, tcpdport, tcpseqno, ackno, \
              tcpflag, tcpwindow, tcpsoption)
   if len(sdata) == 0: 
       tcphs.calccksum(iphs)
   else: 
       tcphs.calccksum(iphs, sdata)

   payload = iphs.bin()
   payload += tcphs.bin()
   if len(sdata) > 0: 
       payload += sdata

   dstr = socket.inet_ntoa(struct.pack('!L',ipdest))
   s.sendto(payload, (dstr, 0))

#
# signal handling
#
def process_child(signum, stack):
    try:
        os.wait()
    except OSError:
	pass

def clean_resources(signum, stack):
    global Fld_udp_on
    global s

    s.close()
    if platform != P_PLAB:
        sys.exit(0)
    print "cleaning resources"
    # close all accepted dummy connections
    for ent in Accepted_list:
        try:
            ent[2].close()
	except (socket.error, socket.herror, socket.gaierror):
	    print "Warn: error in clean_resources"

    # stop UDP flooding
    print "stopping udp flooding"
    if Fld_udp_on.isSet() == True:
        Fld_udp_on.clear()
        print "stopped udp flooding"

    # break synack peeper
    print "breaking pcap reading"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
	for i in range(0, 3):
            s.sendto("a", ("8.8.8.8", PEEP_BREAK_DPORT))
	    time.sleep(0.3)
	s.close()
    except (socket.error, socket.herror, socket.gaierror):
	print "Warn: failed to break pcap block"
    print "stopped pcap reading"

    global ss, sss
    ss.close()
    sss.close()
    sys.exit(0)

signal.signal(signal.SIGCHLD, process_child)
signal.signal(signal.SIGINT, clean_resources)

#
# main
#
if len(sys.argv) < 2:
    print "bad arguments, specify port"
    sys.exit(0)
MPTCP_PORT = int(sys.argv[1])
platform = 0
if len(sys.argv) == 3:
    platform = int(sys.argv[2])
    if platform != P_LINUX and platform != P_PLAB:
        print "Unsupported platform"
	sys.exit(0)

#
# create dummy TCP socket
#   for planetlab we need to bind a port to let NM know that 
#   we're waiting at this port. 
#
if platform == P_PLAB:
    # peep syn ack from OS
    th_peeper = threading.Thread(target=peep_os_synack)
    th_peeper.setDaemon(True)
    th_peeper.start()

    # dummy TCP responder
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ss.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    ss.bind(('', MPTCP_PORT))
    ss.listen(5)

    # UDP flooding control
    sss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sss.bind(('', UDP_FLOOD_CTL_PORT))

#
# create raw socket
#
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

while True: 

  if platform == P_PLAB:
      try:
         inputready,outputready,exceptready = select.select([s, ss, sss], [], [])
      except select.error, e:
          if e[0] == errno.EINTR: continue
          else: break
  else:
      try:
         inputready,outputready,exceptready = select.select([s], [], [])
      except select.error, e:
          if e[0] == errno.EINTR: continue
          else: break
   
  if len(inputready) == 0: continue

  if platform == P_PLAB:
      recvready = 0
      for ready in inputready:
          # Main socket
          if ready == s:
              recvready = 1
	      continue
	  # Dummy listening socket
          elif ready == ss:
	      conn, addr = ss.accept()
#    	      print "dummy accepted by", addr[0], addr[1]
    	      conn.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
	      Accepted_list.append((struct.unpack('!L', \
			      socket.inet_pton(socket.AF_INET, addr[0]))[0], \
			      addr[1], conn))
	      continue
	  # UDP flooding control
	  elif ready == sss:
	      data, address = sss.recvfrom(4)
	      if struct.unpack('!L', data[0:4])[0] == FLOOD_UDP_START:
#	          print "got UDP_START current state", Fld_udp_on.isSet()
	      	  if Fld_udp_on.isSet() == False:
	              th_flooder = threading.Thread(target=flood_udp)
		      th_flooder.setDaemon(True)
	      	      th_flooder.start()
#		      print "UDP flooder has been started"
	      elif struct.unpack('!L', data[0:4])[0] == FLOOD_UDP_STOP:
#	          print "got UDP_STOP current state", Fld_udp_on.isSet()
	          if Fld_udp_on.isSet() == True:
		      Fld_udp_on.clear()
#		      print "UDP flooder has been stopped"
	      sss.sendto(struct.pack('!L', FLOOD_UDP_CONFIRMED), address)
	      continue
      if recvready == 0: 
          continue

  # receive a packet
  (rcvddata, recvaddr) = s.recvfrom(65565)

  # parse ip header
  ipdata = rcvddata[0:20]
  iph = tcplib.iphdr()
  iph.parsehdr(ipdata)

  # parse tcp header
  tcpheader = rcvddata[iph.hdrlen:iph.hdrlen+20]
  tcph = tcplib.tcphdr()
  tcph.parsehdr(tcpheader)
  datalen = len(rcvddata) - iph.hdrlen - tcph.hdrlen
 
  if tcph.dstport != MPTCP_PORT: continue
  elif tcph.flag & tcplib.TH_RST: continue
  elif iph.ttl == 1: continue

  # don't reply to pure ack
  if datalen == 0 and \
    (tcph.flag & tcplib.TH_SYN) == 0 and (tcph.flag & tcplib.TH_FIN) == 0:
    continue

  # get payload
  data = rcvddata[iph.hdrlen + tcph.hdrlen : len(rcvddata)]
  # get header data including options
  rcvhdrdata = rcvddata[0:iph.hdrlen + tcph.hdrlen]

  # get peeped ISN
  pisn = 0
  if platform == P_PLAB and (tcph.flag & tcplib.TH_SYN):
      for i in range(1, 3):
	  Peeper_lock.acquire()
          for sa in reversed(Peeped_synacks):
              if sa[0] == iph.srcaddr and sa[1] == tcph.srcport:
	          pisn = sa[2]
		  break
	  Peeper_lock.release()
	  if pisn != 0:
	      break
	  time.sleep(0.01)
      if pisn == 0:
	  # No peeped ISN, ignore receiving SYN
	  continue

  pid = os.fork()
  if pid == 0:
    tcpackno = tcph.seqno + datalen	
    tcpsport = tcph.dstport 
    tcpdport = tcph.srcport 
    ipsrc = iph.dstaddr
    ipdest = iph.srcaddr
    if pisn != 0:
        tcpseqno = pisn
    
    # SYN DATA reception
    if tcph.flag & tcplib.TH_SYN and datalen > 0:
	mssoption = tcplib.create_mss(MSSval-1)
	wsoption = tcplib.create_winscale(WSval-1)
	tcpwindow -= 1 
	TSval -= 1
    #
    # parse tcp option
    #
    tcpo = tcplib.tcpopt()
    tcpoption = rcvddata[iph.hdrlen + 20 : iph.hdrlen + tcph.hdrlen]
    tsecr = 0

    tcpsoption = ""
    if tcph.flag & tcplib.TH_SYN:
        tcpsoption = mssoption + wsoption + sackokoption
    olen = len(tcpoption)
    idx = 0
    while olen > 0:
        kind = struct.unpack('b', tcpoption[idx:idx+1])[0]
	if kind == 0: break # EOF
	if kind == 1: # NOP
	    idx += 1
	    olen -= 1
	    continue
	optlen = struct.unpack('b', tcpoption[idx+1:idx+2])[0]

	if platform == P_PLAB and kind == tcplib.TO_TIMESTAMP and optlen == 10 \
	     and tcph.flag & tcplib.TH_SYN == 1:
	     pass
	elif kind == tcplib.TO_TIMESTAMP and optlen == 10:
	    rcv_syntsecr = tcplib.unpack_timestamp(tcpoption[idx+2:idx+10])[1]
	    if tcph.flag & tcplib.TH_SYN and rcv_syntsecr != 0:
	        if rcv_syntsecr == SynTsEcr:
	            sigval = 2
	        else:
	            sigval = 4
	        mssoption = tcplib.create_mss(MSSval-sigval)
	        wsoption = tcplib.create_winscale(WSval-sigval)
	        tcpwindow -= sigval
	        TSval = rcv_syntsecr
	        tcpsoption = mssoption + wsoption + sackokoption
	    tsecr = tcplib.unpack_timestamp(tcpoption[idx+2:idx+10])[0]
	    tcpsoption += tcplib.create_timestamp(TSval, tsecr)
	elif kind == tcplib.TO_MP_CAPABLE and optlen == 12:
	    if datalen is 0:
	        mssoption = tcplib.create_mss(MSSval-2)
	        wsoption = tcplib.create_winscale(WSval-2)
	        tcpwindow -= 2 
	        tsoption = tcplib.create_timestamp(TSval-2, tsecr)
	        tcpsoption = mssoption + wsoption + sackokoption + tsoption
	    tcpsoption += tcpoption[idx:idx+12]
	elif kind == tcplib.TO_MP_DATA and optlen == 16:
	    dsn = tcplib.unpack_mpdata(tcpoption[idx+2:idx+16])
	    tcpsoption += tcplib.create_mpack(dsn[0]+dsn[1])
	idx += optlen
	olen -= optlen
	
    tcpflag = tcplib.TH_ACK

    if tcph.flag & tcplib.TH_SYN: 
        tcpflag |= tcplib.TH_SYN 
        datalen = 1
    if tcph.flag & tcplib.TH_FIN: 
        datalen = 1
    if tcpflag & tcplib.TH_SYN or tcpflag & tcplib.TH_FIN or datalen > 0:
        if not tcpflag & tcplib.TH_SYN:
	    tcpseqno = tcph.ackno
        tcpackno = tcph.seqno + datalen
	# special hack parse
        if len(data) > 0 and tcph.flag & tcplib.TH_SYN:
            dhead = struct.unpack('!B', data[0:1])[0]
	    if dhead == Adv_syndata_ack or dhead == Hdrdata_and_advsyndata_ack:
		tcpackno += len(data)
        send_packet()

    if tcph.flag & tcplib.TH_FIN:
        tcpflag |= tcplib.TH_FIN
	send_packet()
	if platform == P_PLAB:
#	    print "Got FIN, closing dummy accepted connection too", socket.inet_ntop(socket.AF_INET, struct.pack('!L', iph.srcaddr)), tcph.srcport
	    close_accepted_so(iph.srcaddr, tcph.srcport)

    sys.exit(0)

