# vim:set ts=4 sw=4 et nowrap syntax=python ff=unix:
#
# Copyright 2011-2018 Mark Crewson <mark@crewson.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from io import BytesIO as StringIO
import tempfile

from myapp.asyncsvr import LineProtocol, TCPServer
from myapp.string_conversion import convert_to_integer, convert_to_seconds

##############################################################################

class HTTPProtocol (LineProtocol):

    def on_request_received (self, request):
        pass

    ##########################################################################

    options = { 'idle_timeout' : ('10s', convert_to_seconds),
                'max_headers'  : ('500', convert_to_integer),
                'max_header_size' : ('16384', convert_to_integer),
              }

    _firstline = True
    _header = ''
    _length = 0
    _persistent = True

    _saved_timeout = None
    _received_header_count = 0
    _received_header_size = 0

    def __init__ (self, **kw):
        super(HTTPProtocol, self).__init__()
        self._parse_options(HTTPProtocol.options, kw)
        self.requests = []
        self.data_buffer = []
        self.is_handling_request = False
        
    def on_connection_made (self):
        self.channel.set_timeout(self.idle_timeout)

    def on_connection_lost (self):
        self.channel.set_timeout(None)
        for req in self.requests:
            req.connection_lost()

    def on_timeout (self):
        self.close()

    def on_line_received (self, line):
        self.channel.reset_timeout()

        self._received_header_size += len(line)
        if self._received_header_size > self.max_header_size:
            self.respond_400()
            return

        # if currently handling a request, buffer the data for later..
        if self.is_handling_request:
            self.data_buffer.append(line)
            self.data_buffer.append('\r\n')
            return

        if self._firstline:
            self.requests.append(RequestParse(self))
            self._firstline = False

            parts = line.split()
            if len(parts) != 3:
                self.respond_400()
                return
            command, path, version = parts
            try:
                command.decode("ascii")
            except UnicodeDecodeError, why:
                self.respond_400(why)
                return

            self._command = command
            self._path = path
            self._version = version

        elif line == '':
            # end of headers
            if self._header:
                ok = self.handle_one_header(self._header)
                if not ok: return
            self._header = ''
            self.handle_headers_received()
            if self._length == 0:
                self.handle_request_received()
            else:
                self.set_raw_mode()

        elif line[0] in ' \t':
            self._header = self._header + '\n' + line

        else:
            if self._header:
                self.handle_one_header(self._header)
            self._header = line

    def on_raw_data_received (self, data):
        self.channel.reset_timeout()
        if self.is_handling_request:
            self.data_buffer.append(data)
            return

        try:
            self._bodydecoder.data_received(data)
        except Exception, why:
            self.respond_400(why)

    #####

    def handle_one_header (self, line):
        try:
            header, data = line.split(':', 1)
        except ValueError:
            self.respond_400()
            return

        header = header.lower()
        data = data.strip()
        
        if header == 'content-length':
            try:
                self._length = int(data)
            except ValueError:
                self.respond_400()
                self._length = None
                return False
            self._bodydecoder = BasicBodyDecoder(self._length, 
                                                 self.requests[-1].handle_content,
                                                 self.handle_body_received)

        elif header == 'transfer-encoding' and data.lower() == 'chunked':
            self._length = None
            self._bodydecoder = ChunkedBodyDecoder(self.requests[-1].handle_content,
                                                   self.handle_body_received)

        reqheaders = self.requests[-1].request_headers
        values = reqheaders.get_raw_headers(header)
        if values is not None:
            values.append(data)
        else:
            reqheaders.set_raw_headers(header, [data])

        self._received_header_count += 1
        if self._received_header_count > self.max_headers:
            self.respond_400()
            return False

        return True

    def handle_headers_received (self):
        req = self.requests[-1]
        req.parse_cookies()
        self._persistent = self.check_persistence(req, self._version)
        req.got_length(self._length)

        # handle 'Expect: 100-continue' with automated 100 response code,
        # a simplistic implementation of RFC 2686 8.2.3:
        expectcontinue = req.request_headers.get_raw_headers('expect')
        if (expectcontinue and expectcontinue[0].lower() == '100-continue' and self._version == 'HTTP/1.1'):
            self.respond_100()

    def handle_body_received (self, extradata):
        self.handle_request_received()
        self._data_buffer.append(extradata)

    def handle_request_received (self):
        command = self._command
        path = self._path
        version = self._version

        # reset all state variables so we don't interfere wit the next request
        self._length = 0
        self._received_header_count = 0
        self._received_header_size = 0
        self._firstline = True
        self._bodydecoder = None
        del self._command, self._path, self._version

        # disable the idle timeout, in case this request takes a long time
        # to finish generating output
        self._saved_timeout = self.channel.set_timeout(None)

        req = self.requests[-1]
        req.handle_request_received(command, path, version)

    def handle_request_done (self, request):
        if request != self.requests[0]: raise TypeError
        del self.requests[0]

        if self._persistent:
            self.is_handling_request = False
            if self._saved_timeout:
                self.channel.set_timeout(self._saved_timeout)

            data = ''.join(self.data_buffer)
            self.data_buffer = []
            self.set_line_mode(data)
        else:
            self.transfer.close_when_done()
        
    #####

    def check_persistence (self, request, version):
        connection = request.request_headers.get_raw_headers('connection')
        if connection:
            tokens = [ t.lower() for t in connection[0].split(' ') ]
        else:
            tokens = []

        if version == 'HTTP/1.1':
            if 'close' in tokens:
                request.requestHeaders.set_raw_headers('connection', ['close'])
                return False
            else:
                return True
        return False

    def respond_100 (self):
        self.write('HTTP/1.1 100 Continue\r\n\r\n')

    def respond_400 (self, message='Bad Request'):
        self.write('HTTP/1.1 400 %s\r\n\r\n' % (message))
        self.close()

##############################################################################

class BasicBodyDecoder (object):

    def __init__ (self, length, data_cb, finish_cb):
        self.length = length
        self.data_cb = data_cb
        self.finish_cb = finish_cb

    def data_received (self, data):
        if self.data_cb is None:
            raise RuntimeError("BasicBodyDecoder cannot decode data after finishing")

        if self.length is None:
            self.data_cb(data)

        elif len(data) < self.length:
            self.length -= len(data)
            self.data_cb(data)

        else:
            # make the state consistent before invoking any code belong to
            # anyone else in case no_more_data() ends up being called beneath
            # this stack frame
            l = self.length
            dcb = self.data_cb
            fcb = self.finish_cb
            self.data_cb = self.finish_cb = None
            self.length = 0

            dcb(data[:l])
            fcb(data[l:])

    def no_more_data (self):
        # todo
        pass

class ChunkedBodyDecoder (object):

    state = 'CHUNK_LENGTH'

    def __init__ (self, data_cb, finish_cb):
        self.data_cb = data_cb
        self.finish_cb = finish_cb
        self.buffer = ''

    def data_received (self, data):
        data = self.buffer + data
        self.buffer = ''
        while data:
            data = getattr(self, '_%s' % (self.state,))(data)

    def no_more_data (self):
        # todo
        pass

    def _CHUNK_LENGTH (self, data):
        if '\r\n' in data:
            line,rest = data.split('\r\n', 1)
            parts = line.split(';')
            try:
                self.length = int(parts[0], 16)
            except ValueError:
                raise MalformedChunkedDataError('Chunk-size must be an integer')
            if self.length == 0:
                self.state = 'TRAILER'
            else:
                self.state = 'BODY'
            return rest
        else:
            self.buffer = data
            return ''

    def _CRLF (self, data):
        if data.startswith('\r\n'):
            self.state = 'CHUNK_LENGTH'
            return data[2:]
        else:
            self.buffer = data
            return ''

    def _TRAILER (self, data):
        if data.startswith('\r\n'):
            data = data[2:]
            self.state = 'FINISHED'
            self.finish_cb(data)
        else:
            self._buffer = data
        return ''

    def _BODY (self, data):
        if len(data) >= self.length:
            chunk, data = data[:self.length], data[self.length:]
            self.data_cb(chunk)
            self.state = 'CRLF'
            return data
        elif len(data) < self.length:
            self.length -= len(data)
            self.data_cb(data)
            return ''

    def _FINISHED (self, data):
        raise RuntimeError('ChunkedBodyDecoder.data_received called after last chunk was processed')

##############################################################################

class RequestParser:

    def __init__ (self, protocol):
        self.protocol = protocol
        self.request_headers = Headers()
        self.request_cookies = {}
        self.content = None

    def connection_lost (self):
        if self.content is not None:
            self.content.close()

    def got_length (self, length):
        if length is not None and length < 100000:
            self.content = StringIO()
        else:
            self.content = tempfile.TemporaryFile()

    def parse_cookies (self):
        cookieheaders = self.request_headers.get_raw_headers('cookie')
        if cookieheaders is None: return

        for cookietxt in cookieheaders:
            if cookietxt:
                for cook in cookietxt.split(';'):
                    cook = cook.lstrip()
                    try:
                        k,v = cook.split('=', 1)
                        self.request_cookies[k] = v
                    except ValueError:
                        pass

    def handle_content (self, data):
        assert self.content is not None, "cannot handle content when length was not specified"
        self.content.write(data)

    def handle_request_received (self, command, path, version):
        if self.content is not None: self.content.seek(0, 0)

        request = Request(command, path, version,
                          self.request_headers,
                          self.request_cookies,
                          self.content,
                          self.protocol)

        self.protocol.on_request_received(request)

        request.finish()
        self.protocol.handle_request_done(self)

        del self.protocol
        if self.content is not None:
            try:
                self.content.close()
            except OSError:
                pass
            del self.content

##############################################################################

class Request (object):

    finished = 0
    code = 200
    code_message = 'OK'
    started_writing = 0
    chunked = 0

    def __init__ (self, method, uri, version, headers, cookies, body, protocol):
        self.method = method
        self.uri = uri
        self.version = version
        self.reqheaders = headers
        self.reqcookies = cookies
        self.body = body
        self.protocol = protocol

        self.respheaders = Headers()
        self.respcookies = []

    def get_header (self, key):
        value = self.reqheaders.get_raw_headers(key)
        if value is not None:
            return value[-1]

    def get_all_headers (self):
        headers = {}
        for k,v in self.reqheaders.get_all_raw_headers():
            headers[k.lower()] = v[-1]
        return headers

    def get_cookie (self, key):
        return self.reqcookies.get(key)

    def set_response_code (self, code, message=None):
        if not isinstance(code, (int, long)):
            raise TypeError('HTTP response code must be int or long')
        self.code = code
        if message:
            self.code_message = message
        else:
            self.code_message = 'Unknown Status'

    def set_response_header (self, name, value):
        self.respheaders.set_raw_headers(name, [value])

    def add_cookie (self, k, v, expires=None, domain=None, path=None,
                    max_age=None, comment=None, secure=None, httponly=False):
        cookie = k + '=' + v
        if expires: cookie = cookie + '; Expires=' + expires
        if domain: cookie = cookie + '; Domain=' + domain
        if path: cookie = cookie + '; Path=' + path
        if max_age: cookie = cookie + '; Max-Age=' + max_age
        if comment: cookie = cookie + '; Comment=' + comment
        if secure: cookie = cookie + '; Secure'
        if httponly: cookie = cookie + '; HttpOnly'
        self.respcookies.append(cookie)

    def write (self, data):
        if self.finished:
            raise RuntimeError('Request.write called on a request after Request.finish was called.')
        if not self.started_writing:
            self.started_writing = 1
            version = self.version
            code = str(self.code)
            reason = self.code_message
            headers = []

            for name, values in self.respheaders.get_all_raw_headers():
                for value in values:
                    headers.append((name, value))

            # if there is no 'Content-Length' header, we send data in chunked mode,
            # so that we can support pipelining in persistent connections
            if ((version == 'HTTP/1.1') and
                (self.respheaders.get_raw_headers('content-length') is None) and
                self.method != 'HEAD'):
                headers.append(('Transfer-Encoding', 'chunked'))
                self.chunked = 1

            for cookie in self.respcookies:
                headers.append(('Set-Cookie', cookie))

            # write headers
            headerseq = [version + ' ' + code + ' ' + reason + '\r\n']
            headerseq.extend(name + ': ' + value + '\r\n' for name, value in headers)
            headerseq.append('\r\n')
            for el in headerseq:
                self.protocol.write(el)

            if self.method == 'HEAD':
                self.write = lambda data: None
                return

        if data:
            if self.chunked:
                self.protocol.write(_tochunk(data))
            else:
                self.protocol.write(data)

    def finish (self):
        if self.finished: return
        if not self.started_writing:
            self.write('')
        if self.chunked:
            self.protocol.write('0\r\n\r\n')
        self.finished = 1

##############################################################################

class Headers (object):

    _casemappings = { 'content-md5': 'Content-MD5',
                      'dnt': 'DNT',
                      'etag': 'ETag',
                      'p3p': 'P3P',
                      'te': 'TE',
                      'www-authenticate': 'WWW-Authenticate',
                      'x-xss-protection': 'X-XSS-Protection'
                    }

    def __init__ (self, rawheaders=None):
        self.rawheaders = {}
        if rawheaders is not None:
            for name, values in rawheaders.items():
                self.set_raw_headers(name, values)

    def _encodename (self, name):
        if isinstance(name, unicode):
            return name.lower().encode('iso-8859-1')
        return name.lower()

    def _encodevalue (self, value):
        if isinstance(value, unicode):
            return value.encode('utf8')
        return value

    def _encodevalues (self, values):
        newvalues = []
        for value in values:
            newvalues.append(self._encodevalue(value))
        return newvalues

    def _decodevalues (self, values):
        if type(values) is not list:
            return values
        newvalues = []
        for value in values:
            newvalues.append(value.decode('utf8'))
        return newvalues

    def _canonical_name_caps (self, name):
        return self._casemappings.get(name, _dashcapitalize(name))

    def set_raw_headers (self, name, values):
        if not isinstance(values, list):
            raise TypeError("Header entry %r should be a list but found "
                            "instance of %r instead" % (name, type(values)))
        name = self._encodename(name)
        self.rawheaders[name] = self._encodevalues(values)

    def get_raw_headers (self, name, default=None):
        encodedname = self._encodename(name)
        values = self.rawheaders.get(encodedname, default)
        if isinstance(name, unicode):
            return self_decodevalues(values)
        return values

    def get_all_raw_headers (self):
        for k,v in self.rawheaders.items():
            yield self._canonical_name_caps(k), v

    def has_header (self, name):
        return self._encodedname(name) in self.rawheaders

    def remove_header (self, name):
        self.rawheaders.pop(self._encodename(name), None)

##############################################################################

def _tochunk (data):
    return '%x' % (len(data)) + '\r\n' + data + '\r\n'

def _dashcapitalize (name):
    return '-'.join([ word.capitalize() for word in name.split('-') ])

##############################################################################

if __name__ == "__main__":

    from myapp.async import get_reactor

    class MyHttpProtocol (HTTPProtocol):
        def on_request_received (self, request):
            buf = []
            buf.append("DEBUG: method = %s" % (request.method))
            buf.append("DEBUG: uri = %s" % (request.uri))
            buf.append("DEBUG: version = %s" % (request.version))
            buf.append("DEBUG HEADERS:")
            for h,v in request.get_all_headers().items():
                buf.append("  %s: %s" % (h,v))

            c = request.get_cookie("NAME")
            if c:
                buf.append("DEBUG COOKIE:  NAME == \"%s\"" % (c))
                request.add_cookie('secret', c, expires='100', httponly=True)

            if request.body is not None:
                buf.append('DEBUG BODY:')
                reqbody = request.body.read()
                while reqbody != '':
                    buf.append(reqbody)
                    reqbody = request.body.read()

            body = '\n'.join(buf)

            request.set_response_code(200, 'mary had a little lamb')
            request.set_response_header('Content-Type', 'text/plain; charset=UTF-8')
            request.set_response_header('Content-Length', str(len(body)))

            request.write(body)

    class HTTPServer (TCPServer):
        def __init__ (self, **kw):
            super(HTTPServer, self).__init__(MyHttpProtocol, **kw)

    HTTPServer(address=('',8080)).activate()
    get_reactor().start()

##############################################################################
# THE END
