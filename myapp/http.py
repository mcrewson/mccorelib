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
        buf = StringIO()
        buf.write("DEBUG: method = %s\r\n" % (request.method))
        buf.write("DEBUG: uri = %s\r\n" % (request.uri))
        buf.write("DEBUG: clientproto = %s\r\n" % (request.clientproto))
        buf.write("DEBUG HEADERS:\r\n")
        for h,v in request.request_headers.get_all_raw_headers():
            buf.write("  %s: %s\r\n" % (h,v))
        body = buf.getvalue()
        buf.close()

        self.write('HTTP/1.1 200 OK\r\n')
        self.write('Content-Type: text/plain; charset=UTF-8\r\n')
        self.write("Content-Length: %d\r\n" % (len(body)))
        self.write('Connection: close\r\n\r\n')
        self.write(body)

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
        self.transport.set_timeout(self.idle_timeout)

    def on_connection_lost (self):
        self.transport.set_timeout(None)
        for req in self.requests:
            req.connection_lost()

    def on_timeout (self):
        self.close()

    def on_line_received (self, line):
        self.transport.reset_timeout()

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
            self.requests.append(Request(self))
            self._firstline = False

            parts = line.split()
            if len(parts) != 3:
                self.respond_400()
                return
            command, path, version = parts
            try:
                command.decode("ascii")
            except UnicodeDecodeError:
                self.repond_400()
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
        self.transport.reset_timeout()

        if self.is_handling_request:
            self.data_buffer.append(data)
            return

        try:
            self._bodydecoder.data_received(data)
        except:
            self.respond_400()

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
            self._bodydecoder = ChunkedBodyDecoder(self.requets[-1].handle_content,
                                                   self.handle_body_recieved)

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
        self._persistent = self.check_persistence(req, self._version)
        req.got_length(self._length)

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
        self._saved_timeout = self.transport.set_timeout(None)

        req = self.requests[-1]
        req.handle_request_received(command, path, version)

    def handle_request_done (self, request):
        if request != self.requests[0]: raise TypeError
        del self.requests[0]

        if self._persistent:
            self.is_handling_request = False
            if self._saved_timeout:
                self.transport.set_timeout(self._saved_timeout)

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

    def respond_400 (self):
        self.write('HTTP/1.1 400 Bad Request\r\n\r\n')
        self.close()

##############################################################################

class BasicBodyDecoder:

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

            dcb(data[:cl])
            fcb(data[cl:])

    def no_more_data (self):
        # todo
        pass

##############################################################################

class Request:

    def __init__ (self, channel):
        self.channel = channel
        self.transport = self.channel.transport
        self.request_headers = Headers()

    def got_length (self, length):
        if length is not None and length < 100000:
            self.content = StringIO()
        else:
            self.content = tempfile.TemporaryFile()

    def handle_content (self, data):
        self.content.write(data)

    def handle_request_received (self, command, path, version):
        self.content.seek(0, 0)
        self.method, self.uri = command, path
        self.clientproto = version

        self.channel.on_request_received(self)
        self.channel.handle_request_done(self)

    def connection_lost (self):
        if self.content is not None:
            self.content.close()


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

def _dashcapitalize (name):
    return '-'.join([ word.capitalize() for word in name.split('-') ])

##############################################################################

class HTTPServer (TCPServer):

    def __init__ (self, **kw):
        super(HTTPServer, self).__init__(HTTPProtocol, **kw)

##############################################################################

if __name__ == "__main__":

    from myapp.async import get_reactor

    HTTPServer(address=('',8080)).activate()
    get_reactor().start()

##############################################################################
# THE END
