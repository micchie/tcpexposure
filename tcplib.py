# Copyright (C) 2010 WIDE Project.  All rights reserved.
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
from struct import *
import re

#
#  default parameters
#
MPTCP_PORT = 34343
BASEHDRLEN = 40
TCPHLEN = 20

TH_FIN = 0x1
TH_SYN = 0x2
TH_RST = 0x4
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20

TO_EOL = 0
TO_NOP = 1
TO_MSS = 2
TO_WSCALE = 3
TO_SACKOK = 4
TO_TIMESTAMP = 8
TO_MP_CAPABLE = 30
TO_MP_DATA = 31
TO_MP_ACK = 32

class etherhdr:
    def __init__(self, ether_dhost=0, ether_shost=0, type=0x0800):
        self.ether_dst = ether_dhost
	self.ether_src = ether_shost
	self.type = type

    def parsehdr (self, data):
	(hdst, ldst, hsrc, lsrc, self.type) = unpack('!HLHLH', data)
	self.ether_dst = (hdst << 32) + ldst
	self.ether_src = (hsrc << 32) + lsrc

    def bin(self):
	bindata = pack('!HLHLH', \
			(self.ether_dst & 0x0000FFFF00000000) >> 32,\
			(self.ether_dst & 0x00000000FFFFFFFF), \
			(self.ether_src & 0x0000FFFF00000000) >> 32, \
			(self.ether_src & 0x00000000FFFFFFFF), \
			self.type)
	return bindata

def ether_htop(etheraddr):
    s = ""
    s += '%02x:'%((etheraddr & 0x0000FF0000000000) >> 40)
    s += '%02x:'%((etheraddr & 0x000000FF00000000) >> 32)
    s += '%02x:'%((etheraddr & 0x00000000FF000000) >> 24)
    s += '%02x:'%((etheraddr & 0x0000000000FF0000) >> 16)
    s += '%02x:'%((etheraddr & 0x000000000000FF00) >> 8)
    s += '%02x'%(etheraddr & 0x00000000000000FF)
    return s

def ether_ptoh(ether_ptr):
    s = re.sub(':', '', ether_ptr)
    etheraddr = long(s, 16)
    return etheraddr


class iphdr:
    def __init__(self, srcaddr=0, dstaddr=0, length=0, id=0, ttl=0, proto=socket.IPPROTO_TCP):
        self.inith = 0x4500
        self.length = length
        self.id = id
        self.flags = 0
        self.ttl = ttl
        self.proto = proto
        self.hdrcksum = 0
        self.srcaddr = srcaddr
        self.dstaddr = dstaddr


    def parsehdr (self, data):
        (self.inith, self.length, self.id, self.flags, self.ttl, self.proto, \
          self.hdrcksum, self.srcaddr, self.dstaddr) = unpack('!HHHHBBHLL', data)
        self.version = (self.inith >> 12)
        self.hdrlen = ((self.inith >> 8) & 7) * 4
        return

    def bin(self):
		bindata = pack('!HHHHBBHLL',self.inith, self.length, \
							self.id, self.flags, self.ttl, self.proto, \
							self.hdrcksum, self.srcaddr, self.dstaddr)
		return bindata

    def calccksum(self):
	bindata = self.bin()
        sum = 0
        idx = 0
        slen = len(bindata)
        while slen > 1:
          byte = bindata[idx:idx+2]  
          d = unpack('!H', byte)
          sum += d[0]
          idx += 2
          slen -= 2

        if slen == 1:
          byte = bindata[-1:]  
          d = unpack('b', byte)
          sum += d

        sum = (sum & 0xffff) + (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16)
          
        self.hdrcksum = (~sum % 65536)

class udphdr:
    def __init__(self, srcport=0, dstport=0):
        self.srcport = srcport
	self.dstport = dstport
	self.len = 0
	self.checksum = 0

    def calcsum(self, bindata):
        sum = 0
        idx = 0
        slen = len(bindata)
        while slen > 1:
          byte = bindata[idx:idx+2]  
          d = unpack('!H', byte)
          sum += d[0]
          idx += 2
          slen -= 2

        if slen == 1:
          byte = bindata[-1:]  
          d = unpack('b', byte)
          sum += d

        sum = (sum & 0xffff) + (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16)
          
        return (~sum % 65536)

    def bin(self):
        bindata = pack('!HHHH',self.srcport, self.dstport, self.len, \
			self.checksum)
        return bindata

    def parsehdr (self, data):
        (self.srcport, self.dstport, self.len, self.checksum) = unpack('!HHHH', data)
        return
    def calccksum(self, iph, data=None):
        self.checksum = 0
        len = iph.length - 20  # we don't use ip option
        bindata = pack('!LLBBH',iph.srcaddr, iph.dstaddr, 0, iph.proto, len)
        bindata += pack('!HHHH',self.srcport, self.dstport, self.len, self.checksum)
	if data != None: 
	    bindata += data
        self.checksum = self.calcsum(bindata)

    def calclen(self, data=None):
	self.len = 8
	if data != None:
	    self.len += len(data)

class tcphdr:
    def __init__(self, srcport=0, dstport=0, seqno=0, ackno=0, \
                       flag=0, window=0, option=""):
        self.srcport = srcport
        self.dstport = dstport
        self.seqno = seqno
        self.ackno = ackno
        self.hlen = (TCPHLEN + len(option)) / 4 << 4
        self.flag = flag
        self.window = window
        self.option = option
        self.urg = 0
        self.checksum = 0

    def calcsum(self, bindata):
        sum = 0
        idx = 0
        slen = len(bindata)
        while slen > 1:
          byte = bindata[idx:idx+2]  
          d = unpack('!H', byte)
          sum += d[0]
          idx += 2
          slen -= 2

        if slen == 1:
          byte = bindata[-1:]  
          d = unpack('b', byte)
          sum += d

        sum = (sum & 0xffff) + (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16)
          
        return (~sum % 65536)

    def bin(self):
        bindata = pack('!HHLLBBHHH',self.srcport, self.dstport, \
             self.seqno, self.ackno, self.hlen, self.flag, self.window, \
             self.checksum, self.urg)
        bindata += self.option
        return bindata

    def parsehdr (self, data):
        (self.srcport, self.dstport, self.seqno, self.ackno, self.offset,\
         self.flag, self.window, self.checksum, self.urg) = unpack('!HHLLBBHHH', data)
        self.hdrlen = (self.offset >> 4) * 4
        return

    def calccksum(self, iph, data=None):
        self.checksum = 0
        len = iph.length - 20  # we don't use ip option
        bindata = pack('!LLBBH',iph.srcaddr, iph.dstaddr, 0, iph.proto, len)
        bindata += pack('!HHLLBBHHH',self.srcport, self.dstport, \
             self.seqno, self.ackno, self.hlen, self.flag, self.window, \
             self.checksum, self.urg)
        bindata += self.option
	if data != None: 
	    bindata += data
        self.checksum = self.calcsum(bindata)

class tcpopt:
    def parseopt (self, data):
        olen = len(data)
        if olen == 0: return ""
        idx = 0
        while olen > 0:
          kind = unpack('b', data[idx:idx+1])
          print " kind %d" % kind[0]
          if kind[0] == 0 or kind[0] == 1:
              idx += 1
              olen -= 1
              continue
          optlen = unpack('b', data[idx+1:idx+2])
          print "optlen %d" % optlen[0]
          idx += optlen[0]
          olen -= optlen[0]

    def searchopt (self, data, skind):
        olen = len(data)
        if olen == 0: return ""
        idx = 0
        while olen > 0:
          kind = unpack('b', data[idx:idx+1])
          if kind[0] == 0 or kind[0] == 1:
              if skind == 0 or skind == 1: return 0
              idx += 1
              olen -= 1
              continue
          optlen = unpack('b', data[idx+1:idx+2])
          if skind == kind[0]:
              payload = data[idx+2:idx + optlen[0]]
              return payload
          idx += optlen[0]
          olen -= optlen[0]
        return ""

#
# functions for exising TCP options
#

def create_mss(mss):
   option = pack('!BBH', TO_MSS, 4, mss) 
   return option

def unpack_mss(option):
    mss = unpack('!H', option)[0]
    return mss
       
def create_eop():
   option = pack('!B', 0)
   return option

def create_nop():
   option = pack('!B', 1)
   return option

def create_winscale(count):
   option = pack('!BBB', TO_WSCALE, 3, count)
   return option

def unpack_winscale(option):
   winscale = unpack('!B', option)[0]
   return winscale

def create_timestamp(ts, tsecho):
   option = pack('!BBLL', TO_TIMESTAMP, 10, ts, tsecho)
   return option

def unpack_timestamp(option):
   (tsval, tsecr) = unpack('!LL', option)
   return tsval, tsecr

def create_sackok():
   option = pack('!BB', TO_SACKOK, 2)
   return option

def check_padding(tcpoption):
   padding = ""
   pad = 0
   nop = create_nop()
   if (len(tcpoption) % 4) != 0:
      pad = 4 - len(tcpoption) % 4 
   for i in range(pad):
      padding += nop
   return padding

#
# functions mptcp options
#
def create_mpcapable(token, isn):
   hisn = (isn & 0xFFFF000000000000)
   lisn = (isn & 0x0000FFFFFFFF0000)
   option = pack('!BBLHL', TO_MP_CAPABLE, 12, token, hisn >> 48, lisn >> 16) 
   return option

def unpack_mpcapable(option):
   (token, hisn, lisn) = unpack('!LHL', option) 
   isn = (hisn << 48) + (lisn << 16)
   return token, isn

#def create_mpjoin():

#def create_mpaddr():

def create_mpdata(dseqno, len, sseqno):
   hseq = (dseqno & 0xFFFFFFFF00000000) >> 32
   lseq = dseqno & 0x00000000FFFFFFFF
   option = pack('!BBLLHL', TO_MP_DATA, 16, hseq, lseq, len, sseqno)
   return option

def unpack_mpdata(option):
   (hseq, lseq, len, sseq) = unpack('!LLHL', option)
   seqno = (hseq << 32) + lseq
   return seqno, len, sseq

def create_mpack(seqno):
#   option = pack('!BBL', MP_ACK, 6, seqno) 
   option = pack('!BBLL', TO_MP_ACK, 10, (seqno & 0xFFFFFFFF00000000) >> 32, (seqno & 0x00000000FFFFFFFF)) 
   return option

def unpack_mpack(option):
   (hdack, ldack) = unpack('!LL', option)
   dack = (hdack << 32) + ldack
   return dack

