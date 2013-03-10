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

from ctypes import *
import os
import socket
import struct
import re

#
# C structures for libpcap
#
class In_addr(Structure):
    _fields_ = [("s_addr", c_uint)]

class Sockaddr_in(Structure):
    if os.uname()[0] == 'Linux':
	_fields_ = [("sin_family", c_short), \
		   ("sin_port", c_ushort), \
		   ("sin_addr", In_addr), \
		   ("sin_zero", c_char*8)]
    elif os.uname()[0] == 'FreeBSD' or os.uname()[0] == 'Darwin':
	_fields_ = [("sin_len", c_ubyte), \
		   ("sin_family", c_ubyte), \
		   ("sin_port", c_ushort), \
		   ("sin_addr", In_addr), \
		   ("sin_zero", c_char*8)]

# For linux, sockaddr_llc instead of sockaddr_dl
IFHWADDRLEN = 6
__LLC_SOCK_SIZE__ = 16

class Sockaddr_llc(Structure):
    _fields_ = [("sllc_family", c_short), \
        ("sllc_arphrd", c_ushort), \
	("sllc_test", c_ubyte), \
	("sllc_ua", c_ubyte), \
	("sllc_sap", c_ubyte), \
	("sllc_mac", c_ubyte * IFHWADDRLEN), \
	("__pad", c_ubyte * (__LLC_SOCK_SIZE__ - 2 * 2 - 1 * 4 - IFHWADDRLEN)),\
        ("sdl_rcf", c_ushort), \
	("sdl_route", c_ushort * 16)]

# Sockaddr_llc doesn't work, use this to obtain mac address
class Sockaddr_dl_lin(Structure):
    _fields_ = [("sdll_family", c_short), \
	       ("sdll_pad", c_ubyte * 10), \
	       ("sdll_data", c_ubyte * 6)]

class Sockaddr_dl(Structure):
    _fields_ = [("sdl_len", c_ubyte), \
        ("sdl_family", c_ubyte), \
	("sdl_index", c_ushort), \
	("sdl_type", c_ubyte), \
	("sdl_nlen", c_ubyte), \
	("sdl_alen", c_ubyte), \
	("sdl_slen", c_ubyte), \
# This is a stupid hack, sdl_data is array of char in C, but we need to change it to u_char because python cannot handle char array include null-termination\n
	("sdl_data", c_ubyte * 12), \
	("sdl_rcf", c_ushort), \
	("sdl_route", c_ushort * 16)]

class Sockaddr(Structure):
    if os.uname()[0] == 'Linux':
        _fields_ = [("sa_family", c_uint16), ("sa_data", c_byte*14)]
    elif os.uname()[0] == 'FreeBSD' or os.uname()[0] == 'Darwin':
        _fields_ = [("sa_len", c_uint8), \
		   ("sa_family", c_uint8), \
		   ("sa_data", c_byte*14)]

class Pcap_addr_t(Structure):
    pass
Pcap_addr_t._fields_ = [("next", POINTER(Pcap_addr_t)), \
	       ("addr", POINTER(Sockaddr)), \
	       ("netmask", POINTER(Sockaddr)), \
	       ("broadaddr", POINTER(Sockaddr)), \
	       ("dstaddr", POINTER(Sockaddr))]

class Pcap_if_t(Structure):
    pass
Pcap_if_t._fields_ = [("next", POINTER(Pcap_if_t)), \
	       ("name", c_char_p), \
	       ("description", c_char_p), \
	       ("addresses", POINTER(Pcap_addr_t)), \
	       ("flags", c_uint32)]

class Bpf_insn(Structure):
    _fields_ = [("code", c_ushort), \
	       ("jt", c_char), \
	       ("jf", c_char), \
	       ("k", c_int)]

class Bpf_program(Structure):
    _fields_ = [("bf_len", c_uint), \
	       ("bf_insns", POINTER(Bpf_insn))]

class Pcap_stat(Structure):
    _fields_ = [("ps_recv", c_uint), \
	       ("ps_drop", c_uint), \
	       ("ps_ifdrop", c_uint)]

class Pcap_sf(Structure):
    _fields_ = [("rfile", c_void_p), \
	       ("swapped", c_int), \
	       ("hdrsize", c_int), \
	       ("version_major", c_int), \
	       ("version_minor", c_int), \
	       ("base", c_char_p)]

class Pcap_md(Structure):
    _fields_ = [("stat", Pcap_stat), \
	       ("use_bpf", c_int), \
	       ("TotPkts", c_ulong), \
	       ("TotAccepted", c_ulong), \
	       ("TotDrops", c_ulong), \
	       ("TotMissed", c_long), \
	       ("OrigMissed", c_long)]

class Pcap(Structure):
    _fields_ = [("fd", c_int), \
	       ("snapshot", c_int), \
	       ("linktype", c_int), \
	       ("tzoff", c_int), \
	       ("offset", c_int), \
	       ("sf", Pcap_sf), \
	       ("md", Pcap_md), \
	       ("bufsize", c_int), \
	       ("buffer", c_char_p), \
	       ("bp", c_char_p), \
	       ("cc", c_int), \
	       ("pkt", c_char_p), \
	       ("fcode", Bpf_program), \
	       ("errbuf", c_char * 256)]

class Timeval(Structure):
    _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]

class Pcap_pkthdr(Structure):
    _fields_ = [("ts", Timeval), ("caplen", c_uint32), ("len", c_uint32)]


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


#
# C functions for libpcap
#

DLT_EN10MB=1
DLT_PPP=9

class pcaplib:
    def __init__(self, ostype=os.uname()[0], lib=None):
	self.ostype = ostype
	self.lib = lib

	if self.ostype == 'Darwin':
	    try:
	        self.lib = CDLL("libpcap.dylib")
	    except OSError:
		self.lib = None
	elif self.ostype == 'FreeBSD':
	    try:
	        self.lib = CDLL("libpcap.so.5")
	    except OSError:
		self.lib = None
	    if self.lib == None:
	        try:
		    self.lib = CDLL("libpcap.so.7")
		except OSError:
		    self.lib = None
	    if self.lib == None:
	        try:
		    self.lib = CDLL("libpcap.so")
		except OSError:
		    self.lib = None
	elif self.ostype == 'Linux':
	    try: 
	        self.lib = CDLL("libpcap.so.0.8")
	    except OSError:
		self.lib = None
	    if self.lib == None:
	        try: 
	            self.lib = CDLL("libpcap.so.0.9")
	        except OSError:
		    self.lib = None

	if self.lib != None:
	    self.lib.pcap_open_live.restype = POINTER(Pcap)
	    self.lib.pcap_geterr.restype = c_char_p
	    self.lib.pcap_datalink_val_to_name.restype = c_char_p

    def Pcap_findalldevs(self):
	devlist = []
	errbuf = create_string_buffer("", 255)
	alldevs_p = c_void_p(None)
	err = self.lib.pcap_findalldevs(byref(alldevs_p), errbuf)
	if err:
	    print "libpcap.pcap_find_alldevs: failed", errbuf.value
	    return devlist, err
	dev = cast(alldevs_p, POINTER(Pcap_if_t))
	while(1):
	    devent = []
  	    try: 
	        devent.append(dev.contents.name)
	    except ValueError: 
	        break
	    if len(dev.contents.name) > 6:
		dev = dev.contents.next
		continue

	    addrs = dev.contents.addresses
	    while(1):
		addrent = [] # (family, laddr, nmask, baddr)
		# obtain local IP address
		try: 
		    addr = addrs.contents.addr
		    addrent.append(addr.contents.sa_family)
		except ValueError:
		    pass

		if len(addrent) > 0:
		    if addrent[0] == socket.AF_INET:
		        sin = cast(addr, POINTER(Sockaddr_in))
			addrent.append(struct.unpack('!L', \
				c_uint(sin.contents.sin_addr.s_addr))[0])
			# obtain netmask of local IP address
			try:
			    netmask = addrs.contents.netmask
			    sin = cast(netmask, POINTER(Sockaddr_in))
			    addrent.append(struct.unpack('!L', \
				c_uint(sin.contents.sin_addr.s_addr))[0])
			except ValueError:
			    addrent.append(0)

			# obtain broadcast address of local IP address
			try:
			    broadaddr = addrs.contents.broadaddr
			    sin = cast(broadaddr, POINTER(Sockaddr_in))
			    addrent.append(struct.unpack('!L', \
				c_uint(sin.contents.sin_addr.s_addr))[0])
			except ValueError:
			    addrent.append(0)

		    elif (self.ostype == 'FreeBSD' or self.ostype == 'Darwin') \
				       and addrent[0] == 18:
			sdl = cast(addr, POINTER(Sockaddr_dl))
			namlen = sdl.contents.sdl_nlen
			s = ""
			for i in range(namlen, namlen+5):
			    s += '%02x:'%sdl.contents.sdl_data[i]
			s += '%02x'%sdl.contents.sdl_data[namlen+5]
			addrent.append(ether_ptoh(s))

		    elif self.ostype == 'Linux' and addrent[0] == 17:
			sdll = cast(addr, POINTER(Sockaddr_dl_lin))
			s = ""
			for i in range(0, 5):
			    s += '%02x:'%sdll.contents.sdll_data[i]
			s += '%02x'%sdll.contents.sdll_data[5]
			addrent.append(ether_ptoh(s))

		    devent.append(addrent)

		try:
		    addrs = addrs.contents.next
		except ValueError:
		    break

	    devlist.append(devent)
	    dev = dev.contents.next
	self.lib.pcap_freealldevs(alldevs_p)
	return devlist, err

    def Pcap_open_live(self, device, snaplen=65535, promisc=1, to_ms=2000):
	errbuf = create_string_buffer("", 255)

	descrip = self.lib.pcap_open_live(device, snaplen, promisc, \
			to_ms, errbuf)
	if errbuf.value != "":
	    print "libpcap.pcap_open_live: failed", errbuf.value
	    return None
	return descrip

    def Pcap_close(self, descrip):
	if descrip == None:
	    return
	self.lib.pcap_close(descrip)
	return

    # We also set the compiled filter and free it
    def Pcap_compile(self, descrip, str, optimize=1, netmask=0):
	fp = Bpf_program()
	retval = self.lib.pcap_compile(descrip, byref(fp), str, optimize, netmask)
	if retval == -1:
	    print 'libpcap.pcap_compile: failed(%d) %s'%\
		(retval, self.lib.pcap_geterr(descrip))
	    return -1
	retval = self.lib.pcap_setfilter(descrip, byref(fp))
	if retval == -1:
	    print 'libpcap.pcap_setfilter: failed(%d) %s'%\
		(retval, self.lib.pcap_geterr(descrip))
	else:
	    self.lib.pcap_freecode(byref(fp))
	return retval

    def Pcap_sendpacket(self, descrip, buf, size):
	retval = self.lib.pcap_sendpacket(descrip, buf, size)
	if retval < 0:
	    print 'libpcap.pcap_sendpacket: failed(%d) %s'%\
		(retval, self.lib.pcap_geterr(descrip))
	return retval

    def Pcap_inject(self, descrip, buf, size):
	retval = self.lib.pcap_inject(descrip, buf, size)
	if retval < 0:
	    print 'libpcap.pcap_inject: failed(%d) %s'%\
		(retval, self.lib.pcap_geterr(descrip))
	return retval

    def Pcap_next_ex(self, descrip):
	pkth_p = c_void_p(None)
	pktd_p = c_void_p(None)
	retval = self.lib.pcap_next_ex(descrip, byref(pkth_p), byref(pktd_p))
	if retval == -1:
	    print 'libpcap.pcap_next_ex: failed(%d) %s'%\
		(retval, self.lib.pcap_geterr(descrip))
	    return retval, None
	elif retval == 0 or retval == -2:
	    return retval, None
	ppkthdr = cast(pkth_p, POINTER(Pcap_pkthdr))
	pdata = cast(pktd_p, POINTER(c_char * ppkthdr.contents.len))
	return retval, pdata.contents[0:ppkthdr.contents.len]

    def Pcap_breakloop(self, descrip):
	self.lib.pcap_breakloop(descrip)
	return

    def Pcap_datalink(self, descrip):
	linktype_val = self.lib.pcap_datalink(descrip)
	return linktype_val

    def Pcap_datalink_val_to_name(self, linktype_val):
	linktype_name = self.lib.pcap_datalink_val_to_name(linktype_val)
	return linktype_name

