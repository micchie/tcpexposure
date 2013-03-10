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

import re

#
# HTTP Header
#
def httphdr_post(host, length):
	httphdr = ""
	httphdr += 'POST /hoge.cgi HTTP/1.1\r\n'
	httphdr += 'Host: %s\r\n'%host
	httphdr += 'Content-Type: application/octet-stream\r\n'
	if length - len(httphdr) - 21 < 0:
		return ''
	elif length - len(httphdr) - 21 < 10:
		httphdr += 'Content-Length: %d\r\n'%(length - len(httphdr) - 21)
	elif length - len(httphdr) - 22 < 100:
		httphdr += 'Content-Length: %d\r\n'%(length - len(httphdr) - 22)
	elif length - len(httphdr) - 23 < 1000:
		httphdr += 'Content-Length: %d\r\n'%(length - len(httphdr) - 23)
	elif length - len(httphdr) - 24 < 10000:
		httphdr += 'Content-Length: %d\r\n'%(length - len(httphdr) - 24)
	else:
		return ''
	httphdr += '\r\n'

	return httphdr

def httphdr_get(host, path):
	httphdr = ""
	httphdr += 'GET %s HTTP/1.1\r\n'%path
	httphdr += 'Host: %s\r\n'%host
	httphdr += '\r\n'

	return httphdr

def httphdr_ok(length):
	httphdr = ""
	httphdr += "HTTP/1.1 200 OK\r\n"
	httphdr += 'Content-Type: application/octet-stream\r\n'
	if length - len(httphdr) - 21 < 0:
		return ''
	elif length - len(httphdr) - 21 < 10:
		httphdr += 'Content-Length: %d\r\n'%(length - len(httphdr) - 21)
	elif length - len(httphdr) - 22 < 100:
		httphdr += 'Content-Length: %d\r\n'%(length - len(httphdr) - 22)
	elif length - len(httphdr) - 23 < 1000:
		httphdr += 'Content-Length: %d\r\n'%(length - len(httphdr) - 23)
	elif length - len(httphdr) - 24 < 10000:
		httphdr += 'Content-Length: %d\r\n'%(length - len(httphdr) - 24)
	else:
		return ''
	httphdr += '\r\n'

	return httphdr

def trim_httphdr(payload):
	if re.match('GET', payload) == None and re.match('POST', payload) == None and re.match('HTTP', payload) == None:
		return payload, 0
	r = re.compile('.*\r\n\r\n', re.DOTALL)
	trimmed = re.sub(r, '', payload, 1)
	return trimmed, 1

def is_http_get(payload, file):
    if re.match('GET /' + file, payload):
        return True
    else:
        return False

hoge_cgi = """
<html>
<body>
<form action='hoge.cgi' method="POST" enctype="multipart/form-data">
<p style="font-size: 18pt">
Submission Form
</p>
<p>
<input type='file' name='logfile' \>
</p>

<p>
<input type='submit' value='submit'\>
</p>
</form>
</body>
</html>
"""

def httphdr_ok_dummy():
    httphdr = ""
    httphdr += "HTTP/1.1 200 OK\r\n"
    httphdr += "Content-Type: text/html\r\n"
    httphdr += 'Content-Length: %d\r\n'%len(hoge_cgi)
    httphdr += '\r\n'
    httphdr += hoge_cgi
    return httphdr
